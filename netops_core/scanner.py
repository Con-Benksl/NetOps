from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import ssl
import sys
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from . import __version__
from .external_tools import run_curated_tools
from .fleet import ssh_invocation
from .models import DiagnosticBundle, Observation, load_bundle
from .remote_collector import REMOTE_COLLECTOR
from .util import (
    MAX_CAPTURE_LIMIT,
    parse_json_strict,
    platform_id,
    read_text_limited,
    run_command,
    trusted_system_environment,
)


TUN_MARKERS = ("tun", "tap", "utun", "wintun", "wireguard", "tailscale", "vpn")
HTTP_POLICY_STATUSES = {401, 403, 407, 429}
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
PROXY_ENV_NAMES = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NETOPS_PROXY_URL",
}
PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
PROXY_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "socks4": 1080,
    "socks4a": 1080,
    "socks5": 1080,
    "socks5h": 1080,
}
_PROXY_FROM_ENVIRONMENT = object()
USER_AGENT = f"NetOps/{__version__}"
NETWORK_PROCESS_ENV_KEYS = {
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "TMPDIR",
}
NETWORK_PROXY_ENV_KEYS = (PROXY_ENV_NAMES - {"NETOPS_PROXY_URL"}) | {
    "NO_PROXY",
    "no_proxy",
}

_RESOLVER_SCRIPT = r"""
import json
import socket
import sys

target, port_text, protocol = sys.argv[1:4]
socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
try:
    answers = socket.getaddrinfo(target, int(port_text), type=socktype)
except socket.gaierror as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
else:
    unique = []
    seen = set()
    for family, _, _, _, sockaddr in answers:
        address = sockaddr[0]
        key = (family, address)
        if key in seen or family not in (socket.AF_INET, socket.AF_INET6):
            continue
        seen.add(key)
        unique.append({
            "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
            "address": address,
        })
    print(json.dumps({"ok": True, "answers": unique}))
"""

_URL_FETCH_SCRIPT = r"""
import json
import sys
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

url, timeout_text = sys.argv[1:3]
try:
    request = urllib.request.Request(url, headers={"User-Agent": __NETOPS_USER_AGENT__})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=float(timeout_text)) as response:
        body = response.read(16384).decode("utf-8", errors="replace")
        status = getattr(response, "status", response.getcode())
except Exception as exc:
    print(json.dumps({
        "ok": False,
        "error_type": type(exc).__name__,
        "error": str(exc),
    }))
else:
    print(json.dumps({"ok": True, "status": status, "body": body}))
""".replace("__NETOPS_USER_AGENT__", repr(USER_AGENT))


def _contains_disallowed_control(value: str) -> bool:
    return any(
        character in {"\u2028", "\u2029"}
        or unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    )


def _network_process_environment(*, include_proxy: bool) -> dict[str, str]:
    environment = trusted_system_environment()
    allowed = {"SSL_CERT_FILE", "SSL_CERT_DIR"}
    if include_proxy:
        allowed.update(NETWORK_PROXY_ENV_KEYS)
    environment.update(
        {key: value for key, value in os.environ.items() if key in allowed}
    )
    return environment


def _run_system_command(
    command: list[str],
    *,
    timeout: float,
    input_text: str | None = None,
    capture_limit: int = MAX_CAPTURE_LIMIT,
) -> dict[str, Any]:
    return run_command(
        command,
        timeout=timeout,
        input_text=input_text,
        env=trusted_system_environment(),
        inherit_env=False,
        capture_limit=capture_limit,
    )


def _run_isolated_python(
    script: str,
    arguments: list[str],
    *,
    timeout: float,
    include_proxy_environment: bool = False,
) -> dict[str, Any]:
    """Run a potentially blocking stdlib network primitive in a killable process."""

    return run_command(
        [sys.executable, "-I", "-S", "-c", script, *arguments],
        timeout=timeout,
        env=_network_process_environment(
            include_proxy=include_proxy_environment,
        ),
        inherit_env=False,
    )


def _isolated_json_payload(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("timed_out"):
        raise TimeoutError("isolated network operation timed out")
    if not result.get("available") or result.get("returncode") != 0:
        raise RuntimeError("isolated network operation failed")
    if result.get("stdout_truncated"):
        raise ValueError("isolated network operation returned truncated JSON")
    try:
        payload = parse_json_strict(result.get("stdout", ""))
    except (TypeError, ValueError) as exc:
        raise ValueError("isolated network operation returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("isolated network operation returned a non-object result")
    return payload


def _validate_declared_target(target: str) -> None:
    if not isinstance(target, str) or not target:
        raise ValueError("target must be a non-empty value without surrounding whitespace")
    if _contains_disallowed_control(target):
        raise ValueError("target must not contain control or format characters")
    if target != target.strip():
        raise ValueError("target must be a non-empty value without surrounding whitespace")
    if target.startswith("-"):
        raise ValueError("target must not start with '-'")
    if len(target) > 254:
        raise ValueError("target is longer than a valid IP address or hostname")
    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass
    try:
        ascii_target = target.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target is not a valid IP address or hostname") from exc
    candidate = ascii_target[:-1] if ascii_target.endswith(".") else ascii_target
    if (
        not candidate
        or len(candidate) > 253
        or any(not HOST_LABEL_RE.fullmatch(label) for label in candidate.split("."))
    ):
        raise ValueError("target is not a valid IP address or hostname")


def _network_target_host(target: str) -> str:
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        return target.encode("idna").decode("ascii")


def _network_http_path(path: str) -> str:
    return quote(path, safe="/:@?&=+$,;%-._~!()*'")


def _target_url(target: str, port: int, path: str, *, tls: bool) -> str:
    host = _network_target_host(target)
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    return f"{'https' if tls else 'http'}://{host}:{port}{_network_http_path(path)}"


def _validate_probe_timeout(timeout: float) -> None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0.1 <= timeout <= 60
    ):
        raise ValueError("timeout must be a finite value between 0.1 and 60 seconds")


def _command_observation(
    name: str,
    command: list[str],
    *,
    segment: str,
    timeout: float = 8,
) -> tuple[Observation, dict[str, Any]]:
    result = _run_system_command(command, timeout=timeout)
    if not result["available"]:
        status = "unknown"
        confidence = "low"
        limitations = [f"未安装系统命令：{command[0]}"]
    elif result["returncode"] == 0:
        status = "unknown"
        confidence = "high"
        limitations = [
            "命令已完成并提供环境证据；这不等于网络健康检查通过"
        ]
    else:
        status = "unknown"
        confidence = "low"
        limitations = ["命令执行失败，或当前权限不足"]
    observation = Observation(
        vantage_point="local",
        segment=segment,
        probe=name,
        status=status,
        metrics={"duration_ms": result.get("duration_ms", 0)},
        evidence={
            "available": result["available"],
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "timed_out": result.get("timed_out", False),
            "execution_status": (
                "succeeded"
                if result["returncode"] == 0 and not result.get("timed_out", False)
                else "failed"
            ),
        },
        confidence=confidence,
        limitations=limitations,
    )
    return observation, result


def _platform_commands(server: bool = False) -> dict[str, list[str]]:
    current = platform_id()
    if current == "linux":
        commands = {
            "addresses": ["ip", "-j", "address"],
            "routes": ["ip", "-j", "route", "show", "table", "all"],
            "rules": ["ip", "-j", "rule"],
            "dns": ["resolvectl", "status"],
        }
        if server:
            commands.update(
                {
                    "listeners": ["ss", "-H", "-lntup"],
                    "services": [
                        "systemctl",
                        "--no-pager",
                        "--plain",
                        "list-units",
                        "--type=service",
                        "--state=running",
                    ],
                    "failed_services": [
                        "systemctl",
                        "--no-pager",
                        "--plain",
                        "--failed",
                    ],
                    "firewall_nft": ["nft", "list", "ruleset"],
                    "firewall_ufw": ["ufw", "status", "verbose"],
                    "congestion_control": [
                        "sysctl",
                        "net.ipv4.tcp_congestion_control",
                    ],
                    "qdisc": ["sysctl", "net.core.default_qdisc"],
                }
            )
        return commands
    if current == "macos":
        return {
            "addresses": ["ifconfig", "-a"],
            "routes": ["netstat", "-rn"],
            "default_route": ["route", "-n", "get", "default"],
            "dns": ["scutil", "--dns"],
            "network_state": ["scutil", "--nwi"],
            "system_proxy": ["scutil", "--proxy"],
        }
    if current == "windows":
        commands = {
            "addresses": ["ipconfig", "/all"],
            "routes": ["route", "print"],
            "dns": ["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress | ConvertTo-Json -Depth 4"],
            "interfaces": ["powershell", "-NoProfile", "-Command", "Get-NetIPConfiguration | ConvertTo-Json -Depth 5"],
            "system_proxy": [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress",
            ],
        }
        if server:
            commands["listeners"] = ["netstat", "-ano"]
        return commands
    return {}


def _address_summary(text: str) -> dict[str, Any]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    for token in re.findall(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", text):
        try:
            ipv4.add(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    for token in re.findall(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", text):
        try:
            value = ipaddress.ip_address(token)
            if value.version == 6:
                ipv6.add(str(value))
        except ValueError:
            continue
    lowered = text.lower()
    tun_hints = sorted({marker for marker in TUN_MARKERS if marker in lowered})
    return {
        "ipv4_present": bool(ipv4),
        "ipv6_present": bool(ipv6),
        "ipv4_count": len(ipv4),
        "ipv6_count": len(ipv6),
        "tun_hints": tun_hints,
    }


def _validated_public_ip(value: Any, *, version: int | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("identity provider did not return an IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("identity provider returned an invalid IP address") from exc
    if version is not None and address.version != version:
        raise ValueError(f"identity provider did not return IPv{version}")
    if not address.is_global:
        raise ValueError("identity provider did not return a public IP address")
    return str(address)


def _parse_external_identity(name: str, body: str) -> dict[str, Any]:
    if name == "ipify-v4":
        parsed = parse_json_strict(body)
        if not isinstance(parsed, dict):
            raise ValueError("ipify returned a non-object JSON response")
        return {"ip": _validated_public_ip(parsed.get("ip"), version=4)}

    fields: dict[str, str] = {}
    for line in body.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ip", "loc", "tls", "warp"}:
            fields[key] = value
    parsed = {"ip": _validated_public_ip(fields.get("ip"))}
    if re.fullmatch(r"[A-Z]{2}", fields.get("loc", "")):
        parsed["loc"] = fields["loc"]
    if re.fullmatch(r"[A-Za-z0-9._-]{1,32}", fields.get("tls", "")):
        parsed["tls"] = fields["tls"]
    if fields.get("warp") in {"on", "off", "plus"}:
        parsed["warp"] = fields["warp"]
    return parsed


def _external_identity(*, timeout: float = 8) -> list[Observation]:
    providers = [
        ("ipify-v4", "https://api.ipify.org?format=json"),
        ("cloudflare-trace", "https://www.cloudflare.com/cdn-cgi/trace"),
    ]
    observations: list[Observation] = []
    for name, url in providers:
        started = time.monotonic()
        try:
            result = _run_isolated_python(
                _URL_FETCH_SCRIPT,
                [url, str(timeout)],
                timeout=timeout,
                include_proxy_environment=True,
            )
            payload = _isolated_json_payload(result)
            if payload.get("ok") is not True:
                raise OSError(str(payload.get("error") or "provider request failed"))
            status_code = payload.get("status")
            if status_code != 200:
                raise ValueError(f"identity provider returned HTTP {status_code}")
            body = payload.get("body")
            if not isinstance(body, str):
                raise ValueError("identity provider returned an invalid body")
            parsed = _parse_external_identity(name, body)
            observations.append(
                Observation(
                    vantage_point="local",
                    segment="public-egress",
                    probe=f"external-identity:{name}",
                    status="ok",
                    target=url,
                    protocol="https",
                    metrics={
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "http_status": status_code,
                    },
                    evidence=parsed,
                    confidence="medium",
                    limitations=[
                        "这只是一个外部服务商看到的出口",
                        "该请求可能经过 TUN 或代理",
                        "本次请求按约定使用了已配置的代理环境变量",
                        "为使授权范围保持在声明的服务商内，本次拒绝跳转",
                    ],
                )
            )
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError, json.JSONDecodeError) as exc:
            observations.append(
                Observation(
                    vantage_point="local",
                    segment="public-egress",
                    probe=f"external-identity:{name}",
                    status="failed",
                    target=url,
                    protocol="https",
                    metrics={
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    },
                    evidence={
                        "error": str(exc),
                        "timed_out": isinstance(exc, TimeoutError),
                    },
                    confidence="medium",
                    limitations=[
                        "单个服务商请求失败不能证明整个互联网连接失败",
                        "本次请求按约定使用了已配置的代理环境变量",
                        "为使授权范围保持在声明的服务商内，本次拒绝跳转",
                    ],
                )
            )
    return observations


def _proxy_environment_summary() -> dict[str, Any]:
    variables: dict[str, dict[str, Any]] = {}
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        value = os.environ.get(name)
        if not value:
            continue
        try:
            parsed = _parse_proxy_url(value)
            contains_credentials: bool | None = (
                parsed.username is not None or parsed.password is not None
            )
        except ValueError:
            variables[name] = {
                "scheme": "invalid",
                "contains_credentials": None,
                "valid": False,
            }
        else:
            variables[name] = {
                "scheme": parsed.scheme or "unknown",
                "contains_credentials": contains_credentials,
                "valid": True,
            }
    return {
        "set_variables": variables,
        "values_redacted": True,
    }


def _parse_proxy_url(value: str):
    if _contains_disallowed_control(value):
        raise ValueError("proxy URL contains a control or format character")
    try:
        parsed = urlsplit(value)
        proxy_port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy URL is invalid") from exc
    if (
        parsed.scheme.casefold() not in PROXY_SCHEMES
        or not parsed.hostname
        or (proxy_port is not None and not 1 <= proxy_port <= 65_535)
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("proxy URL must contain a supported scheme and host")
    _validate_declared_target(parsed.hostname)
    return parsed


def _proxy_endpoint_snapshot(
    proxy_env: str | None,
) -> tuple[dict[str, Any], str | None]:
    identity: dict[str, Any] = {
        "state": "not-requested" if proxy_env is None else "unset",
        "source": f"environment:{proxy_env}" if proxy_env else None,
        "scheme": None,
        "host": None,
        "port": None,
        "credentials_present": None,
    }
    if proxy_env is None:
        return identity, None
    value = os.environ.get(proxy_env)
    if not value:
        return identity, None
    try:
        parsed = _parse_proxy_url(value)
    except ValueError:
        identity["state"] = "invalid"
        return identity, None

    scheme = parsed.scheme.casefold()
    identity.update(
        {
            "state": "configured",
            "scheme": scheme,
            "host": _network_target_host(parsed.hostname).casefold(),
            "port": parsed.port or PROXY_DEFAULT_PORTS[scheme],
            "credentials_present": (
                parsed.username is not None or parsed.password is not None
            ),
        }
    )
    return identity, value


def _system_proxy_enabled(observation: Observation | None) -> bool | None:
    if observation is None or observation.status == "failed":
        return None
    if observation.evidence.get("available") is False:
        return None
    if observation.evidence.get("timed_out") is True:
        return None
    if (
        "returncode" in observation.evidence
        and observation.evidence.get("returncode") != 0
    ):
        return None
    explicit = observation.evidence.get("enabled")
    if isinstance(explicit, bool):
        return explicit
    output = str(observation.evidence.get("stdout", ""))
    enabled_patterns = (
        r"(?m)^\s*(?:HTTP|HTTPS|SOCKS|ProxyAutoConfig)Enable\s*:\s*1\s*$",
        r'"ProxyEnable"\s*:\s*1',
        r'"AutoConfigURL"\s*:\s*"(?:https?|file):',
    )
    return any(re.search(pattern, output) for pattern in enabled_patterns)


def _observation_execution_succeeded(observation: Observation) -> bool:
    return observation.status == "ok" or (
        observation.evidence.get("execution_status") == "succeeded"
        and observation.evidence.get("timed_out") is not True
    )


def _observation_execution_failed(observation: Observation) -> bool:
    if observation.status == "failed" or observation.evidence.get("timed_out") is True:
        return True
    if observation.evidence.get("available") is False:
        return False
    return observation.evidence.get("execution_status") == "failed"


def _segment_from_observations(
    observations: list[Observation],
    *,
    success_status: str,
) -> tuple[str, list[str]]:
    """Derive a path claim only from probes that actually exist in the bundle."""

    evidence = [item.observation_id for item in observations]
    if any(_observation_execution_succeeded(item) for item in observations):
        return success_status, evidence
    if any(_observation_execution_failed(item) for item in observations):
        return "failed", evidence
    return "unknown", evidence


def scan_client(
    *,
    external: bool = False,
    tools: tuple[str, ...] | list[str] = (),
    tools_external: bool = False,
) -> DiagnosticBundle:
    selected_tools = list(dict.fromkeys(tools))
    if len(selected_tools) > 1:
        raise ValueError("select exactly one curated tool per scan")
    if tools_external and not selected_tools:
        raise ValueError("--tool-external requires one selected curated tool")
    if selected_tools and not tools_external:
        raise PermissionError(
            "client curated tools require separate --tool-external consent"
        )
    bundle = DiagnosticBundle(mode="client", vantage_points=["local-client"])
    bundle.environment = {
        "platform": {
            "id": platform_id(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "hostname": socket.gethostname(),
        },
        "timezone": time.tzname[0] if time.tzname else "unknown",
        "network_summary": {},
        "commands": {},
        "curated_tools": selected_tools,
    }
    all_output: list[str] = []
    for name, command in _platform_commands(server=False).items():
        observation, result = _command_observation(
            name, command, segment="client-network"
        )
        if name == "system_proxy":
            enabled = _system_proxy_enabled(observation)
            observation.evidence = {
                "available": result["available"],
                "returncode": result["returncode"],
                "enabled": enabled,
                "details_redacted": True,
                "timed_out": result.get("timed_out", False),
            }
        bundle.observations.append(observation)
        bundle.environment["commands"][name] = {
            "available": result["available"],
            "returncode": result["returncode"],
        }
        if name != "system_proxy":
            all_output.extend([result["stdout"], result["stderr"]])
    if platform_id() == "linux" and not any(
        obs.probe == "dns"
        and obs.evidence.get("execution_status") == "succeeded"
        for obs in bundle.observations
    ):
        content = read_text_limited("/etc/resolv.conf")
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="client-network",
                probe="dns-file",
                status="ok" if content else "unknown",
                evidence={"path": "/etc/resolv.conf", "content": content},
                confidence="medium",
                limitations=["静态配置文件可能不包含每条链路各自的 DNS 状态"],
            )
        )
        all_output.append(content)
    summary = _address_summary("\n".join(all_output))
    bundle.environment["network_summary"] = summary
    system_proxy = next(
        (item for item in bundle.observations if item.probe == "system_proxy"),
        None,
    )
    system_proxy_enabled = _system_proxy_enabled(system_proxy)
    proxy_environment = _proxy_environment_summary()
    bundle.environment["control_channel"] = {
        "codex_dependency": "unknown",
        "tun_detected": bool(summary["tun_hints"]),
        "system_proxy_probe": system_proxy.status if system_proxy else "unavailable",
        "system_proxy_enabled": system_proxy_enabled,
        "proxy_environment": proxy_environment,
        "requires_confirmation": True,
    }
    if summary["tun_hints"]:
        bundle.findings.append(
            {
                "severity": "info",
                "segment": "client-network",
                "title": "检测到可能的 TUN/VPN 接口",
                "evidence": [
                    item.observation_id
                    for item in bundle.observations
                    if item.probe in {"addresses", "routes"}
                ],
                "confidence": "medium",
            }
        )
    if (
        summary["tun_hints"]
        or proxy_environment["set_variables"]
        or system_proxy_enabled is True
    ):
        bundle.findings.append(
            {
                "severity": "info",
                "segment": "control-channel",
                "title": "网络变更前需要确认 Agent 控制通道",
                "evidence": [
                    item.observation_id
                    for item in bundle.observations
                    if item.probe in {"addresses", "routes", "system_proxy"}
                ],
                "confidence": "medium",
            }
        )
    if external:
        bundle.observations.extend(_external_identity())
        bundle.limitations.append(
            "外部身份服务商已从当前观测路径收到 HTTPS 请求"
        )
    else:
        bundle.limitations.append(
            "本次未查询公网出口；只有用户明确同意后才可使用 --external"
        )
    if selected_tools:
        bundle.observations.extend(
            run_curated_tools(
                selected_tools,
                mode="client",
                external=tools_external,
            )
        )
        bundle.limitations.append(
            "所选精选工具已按清单说明连接目标或第三方服务"
        )
    local_observations = [
        item for item in bundle.observations if item.segment == "client-network"
    ]
    local_status, local_evidence = _segment_from_observations(
        local_observations,
        success_status="observed",
    )
    bundle.path_segments = [
        {
            "name": "client-local",
            "status": local_status,
            "evidence": local_evidence,
        },
        {
            "name": "access-network",
            "status": "unknown",
            "evidence": [],
            "limitations": ["需要声明目标，并执行协议匹配的节点扫描"],
        },
    ]
    bundle.limitations.append(
        "扫描能发现代理、系统代理或 TUN 线索，但不能仅凭这些线索证明 Agent 当前经过哪一个节点或 VPS"
    )
    return bundle.finish()


def _local_resources() -> dict[str, Any]:
    disk = shutil.disk_usage("/")
    loadavg_getter = getattr(os, "getloadavg", None)
    try:
        loadavg = loadavg_getter() if callable(loadavg_getter) else None
    except OSError:
        loadavg = None
    memory = read_text_limited("/proc/meminfo", 16_384) if platform_id() == "linux" else ""
    return {
        "cpu_count": os.cpu_count(),
        "loadavg": loadavg,
        "disk_root": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
        },
        "memory_source": memory,
    }


def scan_server_local(
    *,
    external: bool = False,
    tools: tuple[str, ...] | list[str] = (),
    tools_external: bool = False,
) -> DiagnosticBundle:
    selected_tools = list(dict.fromkeys(tools))
    if len(selected_tools) > 1:
        raise ValueError("select exactly one curated tool per scan")
    if tools_external and not selected_tools:
        raise ValueError("--tool-external requires one selected curated tool")
    if selected_tools and not tools_external:
        raise PermissionError(
            "server curated tools require separate --tool-external consent"
        )
    bundle = DiagnosticBundle(mode="server", vantage_points=["local-server"])
    bundle.environment = {
        "platform": {
            "id": platform_id(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "hostname": socket.gethostname(),
        },
        "resources": _local_resources(),
        "commands": {},
        "version_checks": {},
        "sensitive_files": {},
        "curated_tools": selected_tools,
    }
    for name, command in _platform_commands(server=True).items():
        observation, result = _command_observation(name, command, segment="vps")
        bundle.observations.append(observation)
        bundle.environment["commands"][name] = {
            "available": result["available"],
            "returncode": result["returncode"],
        }
    if platform_id() == "linux":
        version_candidates = {
            "x-ui": [["x-ui", "version"], ["/usr/local/x-ui/x-ui", "version"]],
            "xray": [
                ["xray", "version"],
                ["/usr/local/x-ui/bin/xray-linux-amd64", "version"],
                ["/usr/local/x-ui/bin/xray-linux-arm64", "version"],
            ],
        }
        for product, candidates in version_candidates.items():
            for command in candidates:
                if shutil.which(
                    command[0], path=trusted_system_environment()["PATH"]
                ) or (
                    Path(command[0]).is_file() and os.access(command[0], os.X_OK)
                ):
                    bundle.environment["version_checks"][product] = _run_system_command(
                        command, timeout=8
                    )
                    break
        for path in (
            "/etc/x-ui/x-ui.db",
            "/usr/local/x-ui/bin/config.json",
            "/etc/xray/config.json",
        ):
            candidate = Path(path)
            try:
                stat = candidate.stat()
                bundle.environment["sensitive_files"][path] = {
                    "exists": True,
                    "size": stat.st_size,
                    "mode": oct(stat.st_mode & 0o777),
                }
            except OSError:
                bundle.environment["sensitive_files"][path] = {"exists": False}
    if external:
        bundle.observations.extend(_external_identity())
    else:
        bundle.limitations.append(
            "本次未查询服务器公网出口；只有用户同意后才可使用 --external"
        )
    if selected_tools:
        bundle.observations.extend(
            run_curated_tools(
                selected_tools,
                mode="server",
                external=tools_external,
            )
        )
        bundle.limitations.append(
            "所选精选工具已按清单说明连接目标或第三方服务"
        )
    local_observations = [
        item for item in bundle.observations if item.segment == "vps"
    ]
    local_status, local_evidence = _segment_from_observations(
        local_observations,
        success_status="observed",
    )
    egress_observations = [
        item for item in bundle.observations if item.segment == "public-egress"
    ]
    egress_status, egress_evidence = _segment_from_observations(
        egress_observations,
        success_status="partially-observed",
    )
    bundle.path_segments = [
        {
            "name": "vps-local",
            "status": local_status,
            "evidence": local_evidence,
        },
        {
            "name": "vps-egress",
            "status": egress_status,
            "evidence": egress_evidence,
            "limitations": ["无法观察上游服务商内部的转发过程"],
        },
    ]
    return bundle.finish()


def scan_server_remote(host: dict[str, Any], *, authorized: bool) -> DiagnosticBundle:
    if not authorized:
        raise PermissionError("remote scans require --authorized")
    command, transport_env = ssh_invocation(host)
    destination = command[-1]
    result = run_command(
        [*command, "python3", "-"],
        timeout=30,
        input_text=REMOTE_COLLECTOR,
        env=transport_env,
        inherit_env=False,
        capture_limit=MAX_CAPTURE_LIMIT,
    )
    bundle = DiagnosticBundle(
        mode="server",
        vantage_points=[f"remote-server:{host.get('alias', 'unknown')}"],
    )
    bundle.environment = {
        "host_alias": host.get("alias"),
        "management_reference": (host.get("management") or {}).get("address"),
    }
    if result["returncode"] == 0 and not result.get("stdout_truncated"):
        try:
            payload = parse_json_strict(result["stdout"])
        except (TypeError, ValueError) as exc:
            payload = {"parse_error": str(exc), "raw": result["stdout"]}
            status = "failed"
        else:
            status = "ok"
            bundle.environment.update(payload)
    else:
        payload = {
            "stderr": result["stderr"],
            "timed_out": result.get("timed_out"),
            "stdout_truncated": result.get("stdout_truncated", False),
            "stderr_truncated": result.get("stderr_truncated", False),
        }
        status = "failed"
    collector_observation = Observation(
        vantage_point=f"remote-server:{host.get('alias', 'unknown')}",
        segment="vps",
        probe="ssh-readonly-collector",
        status=status,
        target=destination,
        protocol="ssh",
        metrics={"duration_ms": result.get("duration_ms", 0)},
        evidence=payload,
        confidence="high" if status == "ok" else "medium",
        limitations=[]
        if status == "ok"
        else ["远端 Python 或 SSH 访问可能不可用"],
    )
    bundle.observations.append(collector_observation)
    bundle.path_segments = [
        {
            "name": "management-path",
            "status": "observed" if status == "ok" else "failed",
            "evidence": [collector_observation.observation_id],
        },
        {
            "name": "vps-local",
            "status": "observed" if status == "ok" else "unknown",
            "evidence": [collector_observation.observation_id],
            "limitations": [] if status == "ok" else ["没有取得远端采集器输出"],
        },
    ]
    bundle.limitations.append(
        "远端扫描只能观察 VPS，不能观察客户端到 VPS 的业务流量路径"
    )
    return bundle.finish()


def _resolve_target(
    target: str,
    port: int,
    protocol: str,
    timeout: float,
) -> tuple[list[dict[str, Any]], Observation]:
    started = time.monotonic()
    try:
        result = _run_isolated_python(
            _RESOLVER_SCRIPT,
            [target, str(port), protocol],
            timeout=timeout,
        )
        payload = _isolated_json_payload(result)
        if payload.get("ok") is not True:
            raise OSError(str(payload.get("error") or "DNS resolution failed"))
        raw_answers = payload.get("answers")
        if not isinstance(raw_answers, list):
            raise ValueError("DNS resolver returned an invalid answers field")
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in raw_answers:
            if not isinstance(item, dict):
                raise ValueError("DNS resolver returned an invalid answer")
            family = item.get("family")
            address = item.get("address")
            if family not in {"ipv4", "ipv6"} or not isinstance(address, str):
                raise ValueError("DNS resolver returned an invalid address")
            parsed_address = ipaddress.ip_address(address)
            if parsed_address.version != (6 if family == "ipv6" else 4):
                raise ValueError("DNS resolver returned a mismatched address family")
            normalized_address = str(parsed_address)
            key = (family, normalized_address)
            if key in seen:
                continue
            seen.add(key)
            unique.append(
                {
                    "family": family,
                    "address": normalized_address,
                }
            )
        return unique, Observation(
            vantage_point="local",
            segment="dns",
            probe="getaddrinfo",
            status="ok" if unique else "failed",
            target=target,
            protocol=protocol,
            metrics={"duration_ms": result.get("duration_ms", 0)},
            evidence={"answers": unique, "timed_out": False},
            confidence="high",
        )
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
        return [], Observation(
            vantage_point="local",
            segment="dns",
            probe="getaddrinfo",
            status="failed",
            target=target,
            protocol=protocol,
            metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
            evidence={
                "error": str(exc),
                "timed_out": isinstance(exc, TimeoutError),
            },
            confidence="high",
        )


def _tcp_probe(target: str, port: int, address: dict[str, Any], timeout: float) -> Observation:
    family = socket.AF_INET6 if address["family"] == "ipv6" else socket.AF_INET
    sockaddr: tuple[Any, ...]
    if family == socket.AF_INET6:
        sockaddr = (address["address"], port, 0, 0)
    else:
        sockaddr = (address["address"], port)
    started = time.monotonic()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
        status = "ok"
        evidence: dict[str, Any] = {"remote_address": address["address"], "port": port}
    except OSError as exc:
        status = "failed"
        evidence = {"error": str(exc), "remote_address": address["address"], "port": port}
    finally:
        sock.close()
    return Observation(
        vantage_point="local",
        segment="node-ingress",
        probe="tcp-connect",
        status=status,
        target=target,
        protocol="tcp",
        address_family=address["family"],
        metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
        evidence=evidence,
        confidence="high",
        limitations=["TCP 连接成功不能证明上层应用协议可用"],
    )


def _tls_probe(target: str, port: int, address: dict[str, Any], timeout: float) -> Observation:
    family = socket.AF_INET6 if address["family"] == "ipv6" else socket.AF_INET
    sockaddr: tuple[Any, ...] = (
        (address["address"], port, 0, 0)
        if family == socket.AF_INET6
        else (address["address"], port)
    )
    started = time.monotonic()
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    context = ssl.create_default_context()
    try:
        raw.connect(sockaddr)
        with context.wrap_socket(raw, server_hostname=target) as wrapped:
            cert = wrapped.getpeercert()
            evidence = {
                "remote_address": address["address"],
                "tls_version": wrapped.version(),
                "cipher": wrapped.cipher()[0] if wrapped.cipher() else None,
                "certificate_subject": cert.get("subject"),
                "certificate_not_after": cert.get("notAfter"),
            }
            status = "ok"
    except (OSError, ssl.SSLError) as exc:
        raw.close()
        evidence = {"error": str(exc), "remote_address": address["address"]}
        status = "failed"
    return Observation(
        vantage_point="local",
        segment="node-ingress",
        probe="tls-handshake",
        status=status,
        target=target,
        protocol="tls",
        address_family=address["family"],
        metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
        evidence=evidence,
        confidence="high",
        limitations=["TLS 握手成功不能证明 VLESS Reality 或 Hysteria2 认证成功"],
    )


def _http_semantics(status_code: int) -> tuple[str, str]:
    """Map an HTTP response to probe status without calling it business health."""
    if status_code in HTTP_POLICY_STATUSES:
        return "failed", "application-policy-rejection"
    if 200 <= status_code < 400:
        return "ok", "http-response"
    if 400 <= status_code < 500:
        return "unknown", "application-client-or-resource-error"
    if 500 <= status_code < 600:
        return "failed", "application-server-error"
    return "unknown", "non-final-http-response"


def _connect_resolved_socket(
    address: dict[str, Any],
    port: int,
    timeout: float,
) -> socket.socket:
    family = socket.AF_INET6 if address["family"] == "ipv6" else socket.AF_INET
    sockaddr: tuple[Any, ...] = (
        (address["address"], port, 0, 0)
        if family == socket.AF_INET6
        else (address["address"], port)
    )
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(sockaddr)
    except Exception:
        connection.close()
        raise
    return connection


class _ResolvedHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        address: dict[str, Any],
        timeout: float,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._netops_address = address

    def connect(self) -> None:
        self.sock = _connect_resolved_socket(
            self._netops_address,
            self.port,
            self.timeout,
        )


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        address: dict[str, Any],
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._netops_address = address

    def connect(self) -> None:
        raw = _connect_resolved_socket(
            self._netops_address,
            self.port,
            self.timeout,
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _http_probe(
    target: str,
    port: int,
    path: str,
    tls: bool,
    timeout: float,
    address: dict[str, Any],
) -> Observation:
    started = time.monotonic()
    network_host = _network_target_host(target)
    network_path = _network_http_path(path)
    if tls:
        connection: http.client.HTTPConnection = _ResolvedHTTPSConnection(
            network_host,
            port,
            address=address,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        connection = _ResolvedHTTPConnection(
            network_host,
            port,
            address=address,
            timeout=timeout,
        )
    try:
        connection.request(
            "HEAD",
            network_path,
            headers={"User-Agent": USER_AGENT},
        )
        response = connection.getresponse()
        evidence = {
            "http_status": response.status,
            "reason": response.reason,
            "content_type": response.getheader("Content-Type"),
            "server": response.getheader("Server"),
            "transport_reachable": True,
        }
        status, application_outcome = _http_semantics(response.status)
        evidence["application_outcome"] = application_outcome
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        evidence = {
            "error": str(exc),
            "transport_reachable": False,
            "application_outcome": "not-observed",
        }
        status = "failed"
    finally:
        connection.close()
    return Observation(
        vantage_point="local",
        segment="destination",
        probe="http-head",
        status=status,
        target=_target_url(target, port, path, tls=tls),
        protocol="https" if tls else "http",
        metrics={
            "duration_ms": int((time.monotonic() - started) * 1000),
            "http_status": evidence.get("http_status"),
        },
        evidence=evidence,
        confidence="high",
        limitations=[
            "HTTP 状态和传输可达性不能证明登录、支付、媒体等业务功能正常",
            "HEAD 请求的表现可能与浏览器页面访问不同",
        ],
    )


def _proxy_http_probe(
    target: str,
    port: int,
    path: str,
    tls: bool,
    proxy_env: str,
    timeout: float,
    *,
    proxy_url: str | None | object = _PROXY_FROM_ENVIRONMENT,
) -> Observation:
    proxy = (
        os.environ.get(proxy_env)
        if proxy_url is _PROXY_FROM_ENVIRONMENT
        else proxy_url
    )
    if proxy is not None and not isinstance(proxy, str):
        raise TypeError("proxy URL snapshot must be a string or None")
    if not proxy:
        return Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="unknown",
            target=target,
            protocol="https" if tls else "http",
            evidence={"error": f"environment variable {proxy_env!r} is not set"},
            confidence="high",
        )
    if _contains_disallowed_control(proxy):
        raise ValueError(
            "proxy URL must not contain CR, LF, NUL, or other control/format characters"
        )
    try:
        _parse_proxy_url(proxy)
    except ValueError as exc:
        raise ValueError("proxy URL is invalid") from exc
    escaped = proxy.replace("\\", "\\\\").replace('"', '\\"')
    config = f'proxy = "{escaped}"\n'
    url = _target_url(target, port, path, tls=tls)
    result = run_command(
        [
            "curl",
            "--disable",
            "--globoff",
            "--silent",
            "--show-error",
            "--output",
            os.devnull,
            "--noproxy",
            "",
            "--max-time",
            str(timeout),
            "--write-out",
            "\nNETOPS_HTTP_STATUS=%{http_code}\nNETOPS_CONTENT_TYPE=%{content_type}\n",
            "--config",
            "-",
            url,
        ],
        timeout=timeout,
        input_text=config,
        env=_network_process_environment(include_proxy=False),
        inherit_env=False,
    )
    status_match = re.search(r"NETOPS_HTTP_STATUS=(\d{3})", result["stdout"])
    http_status = int(status_match.group(1)) if status_match else None
    transport_reachable = result["returncode"] == 0 and http_status not in (None, 0)
    if transport_reachable:
        status, application_outcome = _http_semantics(http_status)
    else:
        status, application_outcome = "failed", "not-observed"
    content_type_match = re.search(r"NETOPS_CONTENT_TYPE=([^\r\n]*)", result["stdout"])
    return Observation(
        vantage_point="local",
        segment="proxy-egress",
        probe="curl-via-proxy",
        status=status,
        target=url,
        protocol="https" if tls else "http",
        metrics={"duration_ms": result.get("duration_ms", 0), "http_status": http_status},
        evidence={
            "proxy_source": f"environment:{proxy_env}",
            "transport_reachable": transport_reachable,
            "application_outcome": application_outcome,
            "content_type": content_type_match.group(1) if content_type_match else None,
            "stderr": result["stderr"],
            "stdout_truncated": result.get("stdout_truncated", False),
            "stderr_truncated": result.get("stderr_truncated", False),
        },
        confidence="high",
        limitations=[
            "无法观察上游代理内部的路由",
            "HTTP 状态和传输可达性不能证明业务功能正常",
        ],
    )


def trace_target(target: str, *, timeout: float = 25) -> Observation:
    _validate_declared_target(target)
    _validate_probe_timeout(timeout)
    current = platform_id()
    if current == "windows":
        command = ["tracert", "-d", "-w", "1000", target]
    elif current == "macos":
        command = ["traceroute", "-n", "-q", "1", "-w", "1", target]
    elif shutil.which(
        "tracepath", path=trusted_system_environment()["PATH"]
    ):
        command = ["tracepath", "-n", target]
    else:
        command = ["traceroute", "-n", "-q", "1", "-w", "1", target]
    result = _run_system_command(command, timeout=timeout)
    path_observed = result["returncode"] == 0 and bool(result["stdout"].strip())
    path_hops: list[str] = []
    for line in result["stdout"].splitlines():
        for token in re.findall(
            r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"
            r"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])",
            line,
        ):
            try:
                address = str(ipaddress.ip_address(token))
            except ValueError:
                continue
            path_hops.append(address)
            break
    return Observation(
        vantage_point="local",
        segment="access-network",
        probe="bounded-route-snapshot",
        status="unknown",
        target=target,
        protocol="icmp-or-udp-tool-default",
        metrics={"duration_ms": result.get("duration_ms", 0)},
        evidence={
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "stdout_truncated": result.get("stdout_truncated", False),
            "stderr_truncated": result.get("stderr_truncated", False),
            "execution_status": "succeeded" if result["returncode"] == 0 else "failed",
            "path_observed": path_observed,
            "path_hops": path_hops,
        },
        confidence="low",
        limitations=[
            "该路径快照可能与实际业务流量走不同路径",
            "路径中缺少部分跳点或去回程不对称属于常见现象",
        ],
    )


def scan_node(
    *,
    target: str,
    port: int,
    protocol: str = "tcp",
    tls: bool = False,
    http: bool = False,
    path: str = "/",
    proxy_env: str | None = None,
    trace: bool = False,
    timeout: float = 8,
    tools: tuple[str, ...] | list[str] = (),
    external: bool = False,
    allow_load: bool = False,
    resolver: str | None = None,
) -> DiagnosticBundle:
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("port must be between 1 and 65535")
    _validate_declared_target(target)
    _validate_probe_timeout(timeout)
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    if protocol == "udp" and (tls or http or proxy_env):
        raise ValueError("--tls, --http, and --proxy-env require --protocol tcp")
    if proxy_env and not http:
        raise ValueError("--proxy-env requires --http")
    if proxy_env and proxy_env not in PROXY_ENV_NAMES:
        raise ValueError(
            "--proxy-env must name a standard proxy variable or NETOPS_PROXY_URL"
        )
    if http and not path.startswith("/"):
        raise ValueError("HTTP path must start with '/'")
    if len(path) > 2048 or _contains_disallowed_control(path):
        raise ValueError(
            "HTTP path must be at most 2048 characters without control or format characters"
        )
    selected_tools = list(dict.fromkeys(tools))
    if len(selected_tools) > 1:
        raise ValueError("select exactly one curated tool per scan")
    if (external or allow_load or resolver) and not selected_tools:
        raise ValueError("--external, --allow-load, and --resolver require --tool")
    proxy_endpoint, proxy_url = _proxy_endpoint_snapshot(proxy_env)
    bundle = DiagnosticBundle(mode="node", vantage_points=["local-client"])
    bundle.environment = {"curated_tools": selected_tools}
    bundle.targets = [
        {
            "target": target,
            "port": port,
            "protocol": protocol,
            "tls": tls,
            "http": http,
            "path": path if http else None,
            "proxy": f"environment:{proxy_env}" if proxy_env else None,
            "proxy_endpoint": proxy_endpoint,
            "trace": trace,
            "curated_tools": selected_tools,
            "resolver": resolver,
        }
    ]
    answers, dns_observation = _resolve_target(target, port, protocol, timeout)
    bundle.observations.append(dns_observation)
    preferred_http_address = answers[0] if answers else None
    successful_tcp_address = False
    if protocol == "tcp":
        tested_families: set[str] = set()
        for answer in answers:
            if answer["family"] in tested_families:
                continue
            tested_families.add(answer["family"])
            tcp_observation = _tcp_probe(target, port, answer, timeout)
            bundle.observations.append(tcp_observation)
            if tcp_observation.status == "ok" and not successful_tcp_address:
                preferred_http_address = answer
                successful_tcp_address = True
            if tls:
                bundle.observations.append(_tls_probe(target, port, answer, timeout))
    else:
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="node-ingress",
                probe="udp-generic",
                status="unknown",
                target=target,
                protocol="udp",
                evidence={"resolved_answers": answers},
                confidence="low",
                limitations=[
                    "通用 UDP 连接不能证明 Hysteria2 或 QUIC 服务正常",
                    "应使用理解对应协议的客户端及其日志复核",
                ],
            )
        )
    if http:
        if proxy_env:
            if proxy_endpoint["state"] == "invalid":
                bundle.observations.append(
                    Observation(
                        vantage_point="local",
                        segment="proxy-egress",
                        probe="curl-via-proxy",
                        status="unknown",
                        target=_target_url(target, port, path, tls=tls),
                        protocol="https" if tls else "http",
                        evidence={
                            "proxy_source": f"environment:{proxy_env}",
                            "proxy_endpoint_state": "invalid",
                            "error": "configured proxy URL is invalid",
                            "transport_reachable": False,
                            "application_outcome": "not-observed",
                        },
                        confidence="high",
                        limitations=[
                            "无效代理值没有被执行或持久化"
                        ],
                    )
                )
            else:
                bundle.observations.append(
                    _proxy_http_probe(
                        target,
                        port,
                        path,
                        tls,
                        proxy_env,
                        timeout,
                        proxy_url=proxy_url,
                    )
                )
        elif preferred_http_address is None:
            bundle.observations.append(
                Observation(
                    vantage_point="local",
                    segment="destination",
                    probe="http-head",
                    status="unknown",
                    target=_target_url(target, port, path, tls=tls),
                    protocol="https" if tls else "http",
                    evidence={
                        "reason": "not-attempted-without-a-resolved-address",
                        "transport_reachable": False,
                        "application_outcome": "not-observed",
                    },
                    confidence="high",
                    limitations=[
                        "受限 DNS 解析没有得到地址，因此未执行 HTTP 请求"
                    ],
                )
            )
        else:
            bundle.observations.append(
                _http_probe(
                    target,
                    port,
                    path,
                    tls,
                    timeout,
                    preferred_http_address,
                )
            )
    trace_observation: Observation | None = None
    if trace:
        trace_observation = trace_target(target, timeout=timeout)
        bundle.observations.append(trace_observation)
    if selected_tools:
        bundle.observations.extend(
            run_curated_tools(
                selected_tools,
                mode="node",
                external=external,
                allow_load=allow_load,
                target=target,
                port=port,
                protocol=protocol,
                resolver=resolver,
                tls=tls,
            )
        )
        bundle.limitations.append(
            "所选精选工具只连接已声明的目标、解析器或清单中说明的服务商"
        )
    ingress_probe = (
        "tls-handshake"
        if tls
        else "tcp-connect"
        if protocol == "tcp"
        else "udp-generic"
    )
    ingress_observations = [
        item for item in bundle.observations if item.probe == ingress_probe
    ]
    ingress_status, ingress_evidence = _segment_from_observations(
        ingress_observations,
        success_status="observed",
    )
    route_observations = [
        item
        for item in bundle.observations
        if item.probe
        in {
            "bounded-route-snapshot",
            "curated-tool:mtr",
            "curated-tool:nexttrace",
            "curated-tool:iperf3",
        }
    ]
    route_succeeded = bool(
        trace_observation
        and trace_observation.evidence.get("path_observed") is True
    ) or any(
        item.probe in {
            "curated-tool:mtr",
            "curated-tool:nexttrace",
            "curated-tool:iperf3",
        }
        and (
            item.status == "ok"
            or item.evidence.get("usable_result") is True
        )
        for item in bundle.observations
    )
    if route_succeeded:
        route_status = "partially-observed"
    elif any(_observation_execution_failed(item) for item in route_observations):
        route_status = "failed"
    else:
        route_status = "unknown"
    proxy_observations = [
        item for item in bundle.observations if item.probe == "curl-via-proxy"
    ]
    proxy_evidence = [item.observation_id for item in proxy_observations]
    if any(
        item.evidence.get("transport_reachable") is True
        for item in proxy_observations
    ):
        # An HTTP policy response proves the proxy chain transported the
        # request even though the destination application rejected it.
        proxy_status = "partially-observed"
    else:
        proxy_status, _ = _segment_from_observations(
            proxy_observations,
            success_status="partially-observed",
        )
    destination_observations = [
        item
        for item in bundle.observations
        if item.probe in {"http-head", "curl-via-proxy"}
    ]
    destination_status, destination_evidence = _segment_from_observations(
        destination_observations,
        success_status="partially-observed",
    )
    client_observations = [
        item
        for item in bundle.observations
        if item.probe
        in {
            "getaddrinfo",
            "tcp-connect",
            "udp-generic",
            "tls-handshake",
            "http-head",
            "curl-via-proxy",
        }
    ]
    client_evidence = [item.observation_id for item in client_observations]
    if any(
        _observation_execution_succeeded(item)
        or item.evidence.get("transport_reachable") is True
        for item in client_observations
    ):
        client_status = "partially-observed"
    else:
        client_status, _ = _segment_from_observations(
            client_observations,
            success_status="partially-observed",
        )
    dns_status, dns_evidence = _segment_from_observations(
        [dns_observation],
        success_status="observed",
    )
    bundle.path_segments = [
        {
            "name": "client-local",
            "status": client_status,
            "evidence": client_evidence,
        },
        {
            "name": "dns",
            "status": dns_status,
            "evidence": dns_evidence,
        },
        {
            "name": "access-network",
            "status": route_status,
            "evidence": [item.observation_id for item in route_observations],
        },
        {
            "name": "node-ingress",
            "status": ingress_status,
            "evidence": ingress_evidence,
        },
        {
            "name": "proxy-core-and-egress",
            "status": proxy_status,
            "evidence": proxy_evidence,
            "limitations": ["需要服务器侧和出口侧观察，才能进行归因"],
        },
        {
            "name": "destination",
            "status": destination_status,
            "evidence": destination_evidence,
        },
    ]
    policy_rejections = [
        item
        for item in bundle.observations
        if item.evidence.get("application_outcome") == "application-policy-rejection"
    ]
    for item in policy_rejections:
        http_status = item.metrics.get("http_status") or item.evidence.get("http_status")
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": item.segment,
                "title": f"HTTP {http_status}：目标服务或代理明确拒绝/限制了请求",
                "evidence": [item.observation_id],
                "confidence": item.confidence,
            }
        )
    failed = [item for item in bundle.observations if item.status == "failed"]
    grouped_failures: dict[tuple[str, str], list[Observation]] = {}
    for item in failed:
        if item in policy_rejections:
            continue
        grouped_failures.setdefault((item.segment, item.probe), []).append(item)
    for (segment, probe), items in grouped_failures.items():
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": segment,
                "title": f"{probe} 未通过",
                "evidence": [item.observation_id for item in items[:10]],
                "confidence": min(
                    (item.confidence for item in items),
                    key=("low", "medium", "high").index,
                ),
            }
        )
    bundle.limitations.append(
        "仅靠本地节点扫描无法观察 VPS 到上游的回程"
    )
    return bundle.finish()


def _parse_time(value: str | None) -> datetime:
    if not value:
        raise ValueError("bundle is missing a timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _comparison_differences(
    left: Observation | None,
    right: Observation | None,
) -> list[dict[str, Any]]:
    if left is None or right is None:
        return [
            {
                "field": "observation",
                "left": "present" if left else "missing",
                "right": "present" if right else "missing",
            }
        ]

    differences: list[dict[str, Any]] = []
    if left.status != right.status:
        differences.append(
            {"field": "status", "left": left.status, "right": right.status}
        )

    exact_metrics = ("http_status", "responses", "requests")
    for key in exact_metrics:
        left_value = left.metrics.get(key)
        right_value = right.metrics.get(key)
        if left_value is not None or right_value is not None:
            if left_value != right_value:
                differences.append(
                    {"field": f"metrics.{key}", "left": left_value, "right": right_value}
                )

    numeric_rules = {
        "duration_ms": (100.0, 2.0),
        "avg_ms": (20.0, 1.5),
        "max_ms": (50.0, 1.5),
        "jitter_ms": (10.0, 2.0),
        "bits_per_second": (1_000_000.0, 1.5),
    }
    for key, (absolute_threshold, ratio_threshold) in numeric_rules.items():
        left_value = left.metrics.get(key)
        right_value = right.metrics.get(key)
        if not isinstance(left_value, (int, float)) or not isinstance(
            right_value, (int, float)
        ):
            continue
        absolute_delta = abs(float(left_value) - float(right_value))
        smaller = min(abs(float(left_value)), abs(float(right_value)))
        larger = max(abs(float(left_value)), abs(float(right_value)))
        ratio = float("inf") if smaller == 0 and larger else (larger / smaller if smaller else 1.0)
        if absolute_delta >= absolute_threshold and ratio >= ratio_threshold:
            differences.append(
                {"field": f"metrics.{key}", "left": left_value, "right": right_value}
            )

    left_loss = left.metrics.get("loss_percent")
    right_loss = right.metrics.get("loss_percent")
    if isinstance(left_loss, (int, float)) and isinstance(right_loss, (int, float)):
        if abs(float(left_loss) - float(right_loss)) >= 5.0:
            differences.append(
                {
                    "field": "metrics.loss_percent",
                    "left": left_loss,
                    "right": right_loss,
                }
            )

    critical_evidence = (
        "application_outcome",
        "transport_reachable",
        "http_status",
        "tls_version",
        "certificate_not_after",
        "answers",
        "path_observed",
        "path_hops",
        "error",
    )
    for key in critical_evidence:
        left_value = left.evidence.get(key)
        right_value = right.evidence.get(key)
        if left_value is not None or right_value is not None:
            if json.dumps(left_value, sort_keys=True, default=str) != json.dumps(
                right_value, sort_keys=True, default=str
            ):
                differences.append(
                    {"field": f"evidence.{key}", "left": left_value, "right": right_value}
                )
    return differences


def compare_bundles(
    first_path: str | Path,
    second_path: str | Path,
    *,
    max_time_delta_seconds: int = 300,
) -> DiagnosticBundle:
    if (
        type(max_time_delta_seconds) is not int
        or not 0 <= max_time_delta_seconds <= 86_400
    ):
        raise ValueError("max_time_delta_seconds must be an integer from 0 to 86400")
    first = load_bundle(first_path)
    second = load_bundle(second_path)
    if first.mode != "node" or second.mode != "node":
        raise ValueError("path comparison requires two node diagnostic bundles")
    if not first.targets or not second.targets:
        raise ValueError("both bundles need an explicit target for path comparison")
    left = first.targets[0]
    right = second.targets[0]
    keys = (
        "target",
        "port",
        "protocol",
        "tls",
        "http",
        "path",
        "proxy",
        "proxy_endpoint",
        "trace",
        "resolver",
        "curated_tools",
    )
    mismatched = [key for key in keys if left.get(key) != right.get(key)]
    if mismatched:
        raise ValueError(f"bundles are not comparable; target fields differ: {mismatched}")
    delta = abs(
        (_parse_time(first.started_at) - _parse_time(second.started_at)).total_seconds()
    )
    if delta > max_time_delta_seconds:
        raise ValueError(
            f"bundles are {int(delta)} seconds apart; maximum is {max_time_delta_seconds}"
        )
    bundle = DiagnosticBundle(
        mode="compare",
        vantage_points=[first.run_id, second.run_id],
        targets=[left],
    )
    bundle.environment = {
        "left": {
            "run_id": first.run_id,
            "mode": first.mode,
            "started_at": first.started_at,
        },
        "right": {
            "run_id": second.run_id,
            "mode": second.mode,
            "started_at": second.started_at,
        },
        "time_delta_seconds": delta,
    }
    def index(bundle_value: DiagnosticBundle) -> dict[tuple[str, str, str | None], Observation]:
        return {
            (item.segment, item.probe, item.address_family): item
            for item in bundle_value.observations
        }
    left_index = index(first)
    right_index = index(second)
    for key in sorted(set(left_index) | set(right_index), key=str):
        left_item = left_index.get(key)
        right_item = right_index.get(key)
        differences = _comparison_differences(left_item, right_item)
        same = not differences
        source_statuses = {
            item.status for item in (left_item, right_item) if item is not None
        }
        comparison_status = (
            "unknown"
            if not same
            else "failed"
            if "failed" in source_statuses
            else "unknown"
            if "unknown" in source_statuses
            else "ok"
        )
        bundle.observations.append(
            Observation(
                vantage_point="comparison",
                segment=key[0],
                probe=f"compare:{key[1]}",
                status=comparison_status,
                target=str(left.get("target")),
                protocol=str(left.get("protocol")),
                address_family=key[2],
                evidence={
                    "left_status": left_item.status if left_item else "missing",
                    "right_status": right_item.status if right_item else "missing",
                    "left_metrics": left_item.metrics if left_item else {},
                    "right_metrics": right_item.metrics if right_item else {},
                    "differences": differences,
                },
                confidence="high",
                limitations=[] if same else ["差异只能确认结果分叉，不能单独说明原因"],
            )
        )
    divergences = [
        item for item in bundle.observations if item.evidence.get("differences")
    ]
    shared_failures = [
        item
        for item in bundle.observations
        if not item.evidence.get("differences") and item.status == "failed"
    ]
    shared_unknowns = [
        item
        for item in bundle.observations
        if not item.evidence.get("differences") and item.status == "unknown"
    ]
    if divergences:
        severity = "warning"
        title = "两份诊断结果存在差异"
        finding_evidence = divergences
    elif shared_failures:
        severity = "warning"
        title = "两份诊断结果一致，但均包含失败观察"
        finding_evidence = shared_failures
    elif shared_unknowns:
        severity = "info"
        title = "两份诊断结果一致，但均包含未知观察"
        finding_evidence = shared_unknowns
    else:
        severity = "info"
        title = "两份诊断结果一致"
        finding_evidence = []
    bundle.findings.append(
        {
            "severity": severity,
            "segment": "comparison",
            "title": title,
            "evidence": [item.observation_id for item in finding_evidence[:10]],
            "confidence": "high",
        }
    )
    bundle.limitations.append(
        "比较结果只对已声明的目标、协议和时间窗口有效"
    )
    return bundle.finish()
