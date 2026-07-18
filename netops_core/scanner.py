from __future__ import annotations

import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from .fleet import ssh_invocation
from .models import DiagnosticBundle, Observation, load_bundle
from .remote_collector import REMOTE_COLLECTOR
from .util import platform_id, read_text_limited, run_command


TUN_MARKERS = ("tun", "tap", "utun", "wintun", "wireguard", "tailscale", "vpn")


def _command_observation(
    name: str,
    command: list[str],
    *,
    segment: str,
    timeout: float = 8,
) -> tuple[Observation, dict[str, Any]]:
    result = run_command(command, timeout=timeout)
    if not result["available"]:
        status = "unknown"
        confidence = "low"
        limitations = [f"{command[0]} is not installed"]
    elif result["returncode"] == 0:
        status = "ok"
        confidence = "high"
        limitations = []
    else:
        status = "unknown"
        confidence = "low"
        limitations = ["command failed or required additional permission"]
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
        }
    if current == "windows":
        commands = {
            "addresses": ["ipconfig", "/all"],
            "routes": ["route", "print"],
            "dns": ["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress | ConvertTo-Json -Depth 4"],
            "interfaces": ["powershell", "-NoProfile", "-Command", "Get-NetIPConfiguration | ConvertTo-Json -Depth 5"],
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


def _external_identity() -> list[Observation]:
    providers = [
        ("ipify-v4", "https://api.ipify.org?format=json"),
        ("cloudflare-trace", "https://www.cloudflare.com/cdn-cgi/trace"),
    ]
    observations: list[Observation] = []
    for name, url in providers:
        started = time.monotonic()
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "NetOps/0.1"})
            with urllib.request.urlopen(request, timeout=8) as response:
                body = response.read(16_384).decode("utf-8", errors="replace")
                status_code = response.status
            parsed: dict[str, Any]
            if name == "ipify-v4":
                parsed = json.loads(body)
            else:
                parsed = {}
                for line in body.splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        if key in {"ip", "loc", "tls", "warp"}:
                            parsed[key] = value
            observations.append(
                Observation(
                    vantage_point="local",
                    segment="public-egress",
                    probe=f"external-identity:{name}",
                    status="ok" if status_code == 200 else "unknown",
                    target=url,
                    protocol="https",
                    metrics={
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "http_status": status_code,
                    },
                    evidence=parsed,
                    confidence="medium",
                    limitations=[
                        "this is the egress seen by one external provider",
                        "a TUN or proxy may have handled this request",
                    ],
                )
            )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            observations.append(
                Observation(
                    vantage_point="local",
                    segment="public-egress",
                    probe=f"external-identity:{name}",
                    status="failed",
                    target=url,
                    protocol="https",
                    evidence={"error": str(exc)},
                    confidence="medium",
                    limitations=["provider failure does not prove general internet failure"],
                )
            )
    return observations


def scan_client(*, external: bool = False) -> DiagnosticBundle:
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
    }
    all_output: list[str] = []
    for name, command in _platform_commands(server=False).items():
        observation, result = _command_observation(
            name, command, segment="client-network"
        )
        bundle.observations.append(observation)
        bundle.environment["commands"][name] = {
            "available": result["available"],
            "returncode": result["returncode"],
        }
        all_output.extend([result["stdout"], result["stderr"]])
    if platform_id() == "linux" and not any(
        obs.probe == "dns" and obs.status == "ok" for obs in bundle.observations
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
                limitations=["static file may not show per-link DNS"],
            )
        )
        all_output.append(content)
    summary = _address_summary("\n".join(all_output))
    bundle.environment["network_summary"] = summary
    if summary["tun_hints"]:
        bundle.findings.append(
            {
                "severity": "info",
                "segment": "client-network",
                "title": "检测到可能的 TUN/VPN 接口",
                "evidence": summary["tun_hints"],
                "confidence": "medium",
            }
        )
    if external:
        bundle.observations.extend(_external_identity())
        bundle.limitations.append(
            "external identity providers received HTTPS requests from the observed path"
        )
    else:
        bundle.limitations.append(
            "public egress was not queried; use --external only with user consent"
        )
    bundle.path_segments = [
        {
            "name": "client-local",
            "status": "observed",
            "evidence": ["addresses", "routes", "dns"],
        },
        {
            "name": "access-network",
            "status": "partially-observed",
            "evidence": [],
            "limitations": ["requires a declared target and protocol-matched node scan"],
        },
    ]
    return bundle.finish()


def _local_resources() -> dict[str, Any]:
    disk = shutil.disk_usage("/")
    try:
        loadavg = os.getloadavg()
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


def scan_server_local(*, external: bool = False) -> DiagnosticBundle:
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
                if shutil.which(command[0]) or (
                    Path(command[0]).is_file() and os.access(command[0], os.X_OK)
                ):
                    bundle.environment["version_checks"][product] = run_command(
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
            "server public egress was not queried; use --external with consent"
        )
    bundle.path_segments = [
        {
            "name": "vps-local",
            "status": "observed",
            "evidence": ["routes", "listeners", "services", "resources"],
        },
        {
            "name": "vps-egress",
            "status": "partially-observed" if external else "unknown",
            "limitations": ["upstream-provider internal forwarding is not visible"],
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
    )
    bundle = DiagnosticBundle(
        mode="server",
        vantage_points=[f"remote-server:{host.get('alias', 'unknown')}"],
    )
    bundle.environment = {
        "host_alias": host.get("alias"),
        "management_reference": (host.get("management") or {}).get("address"),
    }
    if result["returncode"] == 0:
        try:
            payload = json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            payload = {"parse_error": str(exc), "raw": result["stdout"]}
            status = "failed"
        else:
            status = "ok"
            bundle.environment.update(payload)
    else:
        payload = {"stderr": result["stderr"], "timed_out": result.get("timed_out")}
        status = "failed"
    bundle.observations.append(
        Observation(
            vantage_point=f"remote-server:{host.get('alias', 'unknown')}",
            segment="vps",
            probe="ssh-readonly-collector",
            status=status,
            target=destination,
            protocol="ssh",
            metrics={"duration_ms": result.get("duration_ms", 0)},
            evidence=payload,
            confidence="high" if status == "ok" else "medium",
            limitations=[] if status == "ok" else ["remote Python or SSH access may be unavailable"],
        )
    )
    bundle.path_segments = [
        {
            "name": "management-path",
            "status": "observed" if status == "ok" else "failed",
            "evidence": ["ssh-readonly-collector"],
        },
        {
            "name": "vps-local",
            "status": "observed" if status == "ok" else "unknown",
            "limitations": [] if status == "ok" else ["no remote collector output"],
        },
    ]
    bundle.limitations.append(
        "remote scan observes the VPS but not the client-to-VPS application path"
    )
    return bundle.finish()


def _resolve_target(target: str, port: int, protocol: str) -> tuple[list[dict[str, Any]], Observation]:
    socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    started = time.monotonic()
    try:
        answers = socket.getaddrinfo(target, port, type=socktype)
        unique: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for family, _, _, _, sockaddr in answers:
            address = sockaddr[0]
            key = (family, address)
            if key in seen:
                continue
            seen.add(key)
            unique.append(
                {
                    "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                    "address": address,
                }
            )
        return unique, Observation(
            vantage_point="local",
            segment="dns",
            probe="getaddrinfo",
            status="ok" if unique else "failed",
            target=target,
            protocol=protocol,
            metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
            evidence={"answers": unique},
            confidence="high",
        )
    except socket.gaierror as exc:
        return [], Observation(
            vantage_point="local",
            segment="dns",
            probe="getaddrinfo",
            status="failed",
            target=target,
            protocol=protocol,
            metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
            evidence={"error": str(exc)},
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
        limitations=["a successful TCP connect does not prove the application protocol works"],
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
        limitations=["TLS success does not prove VLESS Reality or Hysteria2 authentication"],
    )


def _http_probe(target: str, port: int, path: str, tls: bool, timeout: float) -> Observation:
    started = time.monotonic()
    connection_class = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    kwargs: dict[str, Any] = {"timeout": timeout}
    if tls:
        kwargs["context"] = ssl.create_default_context()
    connection = connection_class(target, port, **kwargs)
    try:
        connection.request("HEAD", path, headers={"User-Agent": "NetOps/0.1"})
        response = connection.getresponse()
        evidence = {
            "http_status": response.status,
            "reason": response.reason,
            "content_type": response.getheader("Content-Type"),
            "server": response.getheader("Server"),
        }
        status = "ok" if 100 <= response.status < 500 else "failed"
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        evidence = {"error": str(exc)}
        status = "failed"
    finally:
        connection.close()
    return Observation(
        vantage_point="local",
        segment="destination",
        probe="http-head",
        status=status,
        target=f"{'https' if tls else 'http'}://{target}:{port}{path}",
        protocol="https" if tls else "http",
        metrics={"duration_ms": int((time.monotonic() - started) * 1000)},
        evidence=evidence,
        confidence="high",
        limitations=[
            "an HTTP response may still be an application or risk-control rejection",
            "HEAD can behave differently from a browser navigation",
        ],
    )


def _proxy_http_probe(
    target: str,
    port: int,
    path: str,
    tls: bool,
    proxy_env: str,
    timeout: float,
) -> Observation:
    proxy = os.environ.get(proxy_env)
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
    escaped = proxy.replace("\\", "\\\\").replace('"', '\\"')
    config = f'proxy = "{escaped}"\n'
    url = f"{'https' if tls else 'http'}://{target}:{port}{path}"
    result = run_command(
        [
            "curl",
            "--silent",
            "--show-error",
            "--output",
            os.devnull,
            "--dump-header",
            "-",
            "--max-time",
            str(int(timeout)),
            "--write-out",
            "\nNETOPS_HTTP_STATUS=%{http_code}\n",
            "--config",
            "-",
            url,
        ],
        timeout=timeout + 2,
        input_text=config,
    )
    status_match = re.search(r"NETOPS_HTTP_STATUS=(\d{3})", result["stdout"])
    http_status = int(status_match.group(1)) if status_match else None
    status = (
        "ok"
        if result["returncode"] == 0 and http_status is not None and http_status < 500
        else "failed"
    )
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
            "headers": result["stdout"].split("NETOPS_HTTP_STATUS=", 1)[0][-8192:],
            "stderr": result["stderr"],
        },
        confidence="high",
        limitations=["the upstream proxy's internal route is not observable"],
    )


def trace_target(target: str, *, timeout: float = 25) -> Observation:
    current = platform_id()
    if current == "windows":
        command = ["tracert", "-d", "-w", "1000", target]
    elif current == "macos":
        command = ["traceroute", "-n", "-q", "1", "-w", "1", target]
    elif shutil.which("tracepath"):
        command = ["tracepath", "-n", target]
    else:
        command = ["traceroute", "-n", "-q", "1", "-w", "1", target]
    result = run_command(command, timeout=timeout)
    status = "ok" if result["returncode"] == 0 else "unknown"
    return Observation(
        vantage_point="local",
        segment="access-network",
        probe="bounded-route-snapshot",
        status=status,
        target=target,
        protocol="icmp-or-udp-tool-default",
        metrics={"duration_ms": result.get("duration_ms", 0)},
        evidence={"stdout": result["stdout"], "stderr": result["stderr"]},
        confidence="low",
        limitations=[
            "this snapshot may not follow the same path as application traffic",
            "missing hops and asymmetric return paths are expected",
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
) -> DiagnosticBundle:
    bundle = DiagnosticBundle(mode="node", vantage_points=["local-client"])
    bundle.targets = [
        {
            "target": target,
            "port": port,
            "protocol": protocol,
            "tls": tls,
            "http": http,
            "proxy": f"environment:{proxy_env}" if proxy_env else None,
        }
    ]
    answers, dns_observation = _resolve_target(target, port, protocol)
    bundle.observations.append(dns_observation)
    if protocol == "tcp":
        tested_families: set[str] = set()
        for answer in answers:
            if answer["family"] in tested_families:
                continue
            tested_families.add(answer["family"])
            bundle.observations.append(_tcp_probe(target, port, answer, timeout))
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
                    "generic UDP connect cannot prove a Hysteria2 or QUIC service is healthy",
                    "use a protocol-aware client and its logs",
                ],
            )
        )
    if http:
        if proxy_env:
            bundle.observations.append(
                _proxy_http_probe(target, port, path, tls, proxy_env, timeout)
            )
        else:
            bundle.observations.append(_http_probe(target, port, path, tls, timeout))
    if trace:
        bundle.observations.append(trace_target(target))
    statuses = [item.status for item in bundle.observations if item.segment == "node-ingress"]
    ingress_status = "failed" if "failed" in statuses and "ok" not in statuses else (
        "observed" if "ok" in statuses else "unknown"
    )
    bundle.path_segments = [
        {"name": "client-local", "status": "partially-observed"},
        {
            "name": "dns",
            "status": "observed" if dns_observation.status == "ok" else "failed",
        },
        {"name": "access-network", "status": "partially-observed" if trace else "unknown"},
        {"name": "node-ingress", "status": ingress_status},
        {
            "name": "proxy-core-and-egress",
            "status": "partially-observed" if proxy_env and http else "unknown",
            "limitations": ["requires server and egress observations for attribution"],
        },
        {
            "name": "destination",
            "status": "partially-observed" if http else "unknown",
        },
    ]
    failed = [item for item in bundle.observations if item.status == "failed"]
    if failed:
        first = failed[0]
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": first.segment,
                "title": f"{first.probe} 未通过",
                "evidence": [first.observation_id],
                "confidence": first.confidence,
            }
        )
    bundle.limitations.append(
        "a local node scan alone cannot observe the VPS-to-upstream return path"
    )
    return bundle.finish()


def _parse_time(value: str | None) -> datetime:
    if not value:
        raise ValueError("bundle is missing a timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compare_bundles(
    first_path: str | Path,
    second_path: str | Path,
    *,
    max_time_delta_seconds: int = 300,
) -> DiagnosticBundle:
    first = load_bundle(first_path)
    second = load_bundle(second_path)
    if not first.targets or not second.targets:
        raise ValueError("both bundles need an explicit target for path comparison")
    left = first.targets[0]
    right = second.targets[0]
    keys = ("target", "port", "protocol")
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
        same = left_item is not None and right_item is not None and left_item.status == right_item.status
        bundle.observations.append(
            Observation(
                vantage_point="comparison",
                segment=key[0],
                probe=f"compare:{key[1]}",
                status="ok" if same else "unknown",
                target=str(left.get("target")),
                protocol=str(left.get("protocol")),
                address_family=key[2],
                evidence={
                    "left_status": left_item.status if left_item else "missing",
                    "right_status": right_item.status if right_item else "missing",
                    "left_metrics": left_item.metrics if left_item else {},
                    "right_metrics": right_item.metrics if right_item else {},
                },
                confidence="high",
                limitations=[] if same else ["a difference identifies a divergence, not its cause"],
            )
        )
    differences = [item for item in bundle.observations if item.status != "ok"]
    bundle.findings.append(
        {
            "severity": "info" if not differences else "warning",
            "segment": "comparison",
            "title": "两份诊断结果一致" if not differences else "两份诊断结果存在差异",
            "evidence": [item.observation_id for item in differences[:10]],
            "confidence": "high",
        }
    )
    bundle.limitations.append(
        "comparison is valid only for the declared target, protocol, and time window"
    )
    return bundle.finish()
