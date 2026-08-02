from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from dataclasses import asdict, dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Callable, Iterable

from .models import Observation
from .util import (
    load_json_limited,
    parse_json_strict,
    platform_id,
    run_command,
    trusted_system_environment,
)


CATALOG_VERSION = "1.0"
LAST_VERIFIED = "2026-07-20"
EXTREME_AVERAGE_LATENCY_MS = 1_000.0
EXTREME_MAXIMUM_LATENCY_MS = 2_000.0


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    name: str
    purpose_zh: str
    category: str
    official_url: str
    license: str
    modes: tuple[str, ...]
    platforms: tuple[str, ...]
    candidates: tuple[str, ...]
    env_var: str
    output_format: str
    network_risk: str
    load_class: str
    data_sent_zh: str
    install_hint_zh: str
    limitations: tuple[str, ...]
    default_timeout: float
    compatibility_baseline: str
    version_args: tuple[str, ...]
    minimum_version: tuple[int, ...] = ()
    capability_args: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    requires_bash_major: int = 0
    distribution_name: str = ""
    expected_sha256: str = ""
    shell_script: bool = False
    confidence: str = "medium"


CURATED_TOOLS = (
    ToolSpec(
        tool_id="mtr",
        name="MTR",
        purpose_zh="连续采样路径延迟、抖动和丢包",
        category="route",
        official_url="https://github.com/traviscross/mtr",
        license="GPL-2.0",
        modes=("node",),
        platforms=("linux", "macos"),
        candidates=("mtr",),
        env_var="NETOPS_TOOL_MTR",
        output_format="json",
        network_risk="declared-target",
        load_class="low",
        data_sent_zh="向用户指定的目标发送少量 TCP 或 UDP 探测包",
        install_hint_zh="通过系统软件包管理器安装 mtr，或设置 NETOPS_TOOL_MTR。",
        limitations=(
            "中间路由器可能限制或忽略探测包",
            "某一跳丢包不能单独证明端到端丢包",
        ),
        default_timeout=35,
        compatibility_baseline=(
            "MTR >=0.95 with all required JSON/report/protocol capabilities; "
            "current upstream stable 0.96"
        ),
        version_args=("--version",),
        # Ubuntu 24.04 and Debian 13 ship 0.95. The adapter separately probes
        # every flag it uses, so the package floor is safe only when that
        # concrete build exposes the complete capability set below.
        minimum_version=(0, 95),
        capability_args=("--help",),
        required_capabilities=(
            "--json",
            "--report",
            "--report-cycles",
            "--no-dns",
            "--tcp",
            "--udp",
            "--port",
        ),
        confidence="medium",
    ),
    ToolSpec(
        tool_id="nexttrace",
        name="NextTrace",
        purpose_zh="生成协议匹配的结构化路由快照",
        category="route",
        official_url="https://github.com/nxtrace/NTrace-core",
        license="GPL-3.0",
        modes=("node",),
        platforms=("linux", "macos", "windows"),
        candidates=("nexttrace",),
        env_var="NETOPS_TOOL_NEXTTRACE",
        output_format="json",
        network_risk="declared-target",
        load_class="low",
        data_sent_zh=(
            "向用户指定的目标发送少量路径探测包；适配器默认关闭第三方 GeoIP 查询"
        ),
        install_hint_zh="安装 NextTrace 官方稳定版，或设置 NETOPS_TOOL_NEXTTRACE。",
        limitations=(
            "路由快照不等于完整物理线路或回程",
            "默认禁用 GeoIP，避免把每一跳地址发送给额外服务",
        ),
        default_timeout=35,
        compatibility_baseline="NextTrace 1.7.1 with --json and disable-geoip",
        version_args=("--version",),
        minimum_version=(1, 7, 1),
        capability_args=("--help",),
        required_capabilities=(
            "--json",
            "--no-color",
            "--no-rdns",
            "--data-provider",
            "--queries",
            "--parallel-requests",
            "--max-hops",
            "--tcp",
            "--udp",
            "--port",
        ),
        confidence="medium",
    ),
    ToolSpec(
        tool_id="dnsdiag",
        name="dnsdiag / dnsping",
        purpose_zh="测量指定 DNS 解析器的延迟、抖动和丢包",
        category="dns",
        official_url="https://github.com/farrokhi/dnsdiag",
        license="BSD-2-Clause",
        modes=("node",),
        platforms=("linux", "macos", "windows"),
        candidates=("dnsping", "dnsping.py"),
        env_var="NETOPS_TOOL_DNSDIAG",
        output_format="text-summary",
        network_risk="declared-resolver",
        load_class="low",
        data_sent_zh="向用户指定的 DNS 解析器查询用户指定的域名",
        install_hint_zh=(
            "安装 dnsdiag 官方发行版，或设置 NETOPS_TOOL_DNSDIAG 指向 dnsping。"
        ),
        limitations=(
            "结果只代表指定解析器、域名和传输方式",
            "必须显式提供 DNS 解析器，NetOps 不会擅自改用公共 DNS",
        ),
        default_timeout=25,
        compatibility_baseline="dnsdiag 2.9.4",
        version_args=(),
        minimum_version=(2, 9, 4),
        distribution_name="dnsdiag",
        capability_args=("-h",),
        required_capabilities=("-c", "--tcp", "-p", "-s"),
        confidence="high",
    ),
    ToolSpec(
        tool_id="testssl",
        name="testssl.sh",
        purpose_zh="检查指定 TLS 服务的协议、证书和服务端默认参数",
        category="tls",
        official_url="https://github.com/testssl/testssl.sh",
        license="GPL-2.0",
        modes=("node",),
        platforms=("linux", "macos"),
        candidates=("testssl.sh", "testssl"),
        env_var="NETOPS_TOOL_TESTSSL",
        output_format="json-file",
        network_risk="declared-target",
        load_class="medium",
        data_sent_zh=(
            "解析用户指定的目标（工具可能执行 DNS 与反向解析），并与该 TLS 服务建立多次受控握手"
        ),
        install_hint_zh="安装 testssl.sh 官方稳定版，或设置 NETOPS_TOOL_TESTSSL。",
        limitations=(
            "适配器执行聚焦检查，不替代完整安全审计",
            "TLS 检查成功不代表代理协议认证成功",
            "工具可能执行目标 DNS 解析和反向 DNS 查询，相关解析器会观察查询",
        ),
        default_timeout=180,
        compatibility_baseline="testssl.sh 3.2.4",
        version_args=("--version",),
        minimum_version=(3, 2, 4),
        capability_args=("--help",),
        required_capabilities=(
            "--quiet",
            "--warnings",
            "--color",
            "--jsonfile",
            "--protocols",
            "--server-defaults",
        ),
        shell_script=True,
        confidence="high",
    ),
    ToolSpec(
        tool_id="ipquality",
        name="IPQuality",
        purpose_zh="汇总当前出口的 IP 类型、信誉和服务可用性线索",
        category="ip-quality",
        official_url="https://github.com/xykt/IPQuality",
        license="AGPL-3.0",
        modes=("client", "server"),
        platforms=("linux", "macos"),
        candidates=(),
        env_var="NETOPS_TOOL_IPQUALITY",
        output_format="json-file",
        network_risk="multiple-providers",
        load_class="medium",
        data_sent_zh="当前出口 IP 会被多个信誉、地理和服务提供商观察",
        install_hint_zh=(
            "下载并审核 IPQuality 官方 ip.sh 后，将 NETOPS_TOOL_IPQUALITY 设置为该文件路径。"
        ),
        limitations=(
            "隐私模式只关闭在线报告，第三方质量查询仍会发生",
            "不同数据库的标签和风险分数可能冲突，不能合成绝对结论",
            "适配器禁止脚本自动安装依赖",
        ),
        default_timeout=360,
        compatibility_baseline=(
            "IPQuality commit 44c35cca002782ddd6364e039be2949a2535d1cc"
        ),
        version_args=(),
        requires_bash_major=4,
        expected_sha256=(
            "69e7a8d0b9018a508fa7a54a3f7e98c9fa8c19eeb6995d60675070361cb76c03"
        ),
        shell_script=True,
        confidence="low",
    ),
    ToolSpec(
        tool_id="iperf3",
        name="iperf3",
        purpose_zh="对用户控制的 iperf3 端点执行限时限速吞吐测试",
        category="performance",
        official_url="https://software.es.net/iperf/",
        license="BSD-3-Clause",
        modes=("node",),
        platforms=("linux", "macos"),
        candidates=("iperf3",),
        env_var="NETOPS_TOOL_IPERF3",
        output_format="json",
        network_risk="declared-target",
        load_class="high",
        data_sent_zh="5 秒内最多按约 10 Mbit/s 向用户指定端点发送测试流量",
        install_hint_zh=(
            "通过系统软件包管理器安装 iperf3，或设置 NETOPS_TOOL_IPERF3。"
        ),
        limitations=(
            "只能对用户拥有或明确授权的 iperf3 服务端执行",
            "限速样本用于链路对比，不代表线路最大带宽",
        ),
        default_timeout=20,
        compatibility_baseline=(
            "iperf3 >=3.16 with all required bounded-client/JSON capabilities; "
            "current upstream stable 3.21"
        ),
        version_args=("--version",),
        # Ubuntu 24.04 provides 3.16 and Debian 13 provides 3.18. Both are
        # admitted only after the local help output proves support for every
        # option the bounded adapter invokes.
        minimum_version=(3, 16),
        capability_args=("--help",),
        required_capabilities=(
            "--client",
            "--port",
            "--time",
            "--bitrate",
            "--connect-timeout",
            "--json",
            "--udp",
        ),
        confidence="high",
    ),
)

TOOL_INDEX = {item.tool_id: item for item in CURATED_TOOLS}
CURATED_ENVIRONMENT_KEYS = {
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "PATH",
    "PATHEXT",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "SystemRoot",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USERPROFILE",
    "WINDIR",
}
NETWORK_HOST_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _validate_network_argument(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty unpadded value")
    if any(
        character in {"\u2028", "\u2029"}
        or unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        raise ValueError(f"{label} must not contain control or format characters")
    if value != value.strip():
        raise ValueError(f"{label} must be a non-empty unpadded value")
    if value.startswith("-"):
        raise ValueError(f"{label} must not start with '-' when running curated tools")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    try:
        candidate = value.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError as exc:
        raise ValueError(f"{label} must be an IP address or hostname") from exc
    if (
        not candidate
        or len(candidate) > 253
        or any(
            not NETWORK_HOST_LABEL_RE.fullmatch(part)
            for part in candidate.split(".")
        )
    ):
        raise ValueError(f"{label} must be an IP address or hostname")


def _curated_environment() -> dict[str, str]:
    """Return only process settings required to launch a local tool.

    Proxy variables and arbitrary application credentials are intentionally not
    inherited: each adapter already declares its observation path and data
    recipients, and a reviewed third-party executable does not need unrelated
    secrets from the agent or shell environment.
    """

    environment = trusted_system_environment()
    for key in CURATED_ENVIRONMENT_KEYS - {"PATH"}:
        if key in environment:
            continue
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _curated_runner(
    runner: Callable[..., dict[str, Any]],
    command: list[str],
    **kwargs: Any,
) -> dict[str, Any]:
    kwargs["env"] = _curated_environment()
    kwargs["inherit_env"] = False
    return runner(command, **kwargs)


def tool_ids() -> tuple[str, ...]:
    return tuple(TOOL_INDEX)


def tool_ids_for_mode(mode: str) -> tuple[str, ...]:
    return tuple(item.tool_id for item in CURATED_TOOLS if mode in item.modes)


def tool_catalog() -> dict[str, Any]:
    return {
        "catalog_version": CATALOG_VERSION,
        "last_verified": LAST_VERIFIED,
        "tools": [asdict(item) for item in CURATED_TOOLS],
    }


def _is_launchable_override(candidate: Path, platform_name: str) -> bool:
    if not candidate.is_file():
        return False
    if platform_name == "windows":
        # Windows does not model POSIX execute bits: os.access(..., X_OK) can
        # accept an arbitrary regular file. Restrict binary overrides to native
        # executable formats; batch files would silently introduce cmd.exe
        # parsing despite the adapter's shell-free argument contract.
        return (
            candidate.suffix.casefold() in {".com", ".exe"}
            and os.access(candidate, os.R_OK)
        )
    try:
        mode = candidate.stat().st_mode
    except OSError:
        return False
    executable_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    return bool(mode & executable_bits) and os.access(candidate, os.X_OK)


def _discover(spec: ToolSpec) -> tuple[str | None, str]:
    current = platform_id()
    override = os.environ.get(spec.env_var)
    if override:
        candidate = Path(override).expanduser()
        usable = (
            os.access(candidate, os.R_OK)
            if spec.shell_script
            else _is_launchable_override(candidate, current)
        )
        if candidate.is_file() and usable:
            return str(candidate.resolve()), f"environment:{spec.env_var}"
        return None, f"invalid-environment:{spec.env_var}"
    for name in spec.candidates:
        found = shutil.which(name, path=trusted_system_environment()["PATH"])
        if found and (
            current != "windows"
            or spec.shell_script
            or _is_launchable_override(Path(found), current)
        ):
            return found, "PATH"
    return None, "not-found"


def _windows_is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _windows_windivert_ready(executable: str) -> bool:
    directory = Path(executable).resolve().parent
    dll_present = any(
        (directory / name).is_file()
        for name in ("WinDivert.dll", "WinDivert64.dll", "WinDivert32.dll")
    )
    driver_present = any(
        (directory / name).is_file()
        for name in ("WinDivert.sys", "WinDivert64.sys", "WinDivert32.sys")
    )
    return dll_present and driver_present


def _parse_version(text: str) -> tuple[int, ...] | None:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def _version_at_least(actual: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    width = max(len(actual), len(minimum))
    return (*actual, *(0 for _ in range(width - len(actual)))) >= (
        *minimum,
        *(0 for _ in range(width - len(minimum))),
    )


def _has_capability(text: str, flag: str) -> bool:
    return bool(
        re.search(rf"(?<![A-Za-z0-9_-]){re.escape(flag)}(?![A-Za-z0-9_-])", text)
    )


def _compatibility_check(
    spec: ToolSpec,
    path: str,
    current_platform: str,
    runner: Callable[..., dict[str, Any]],
) -> tuple[bool, str, dict[str, Any]]:
    """Perform local-only fail-closed checks before a curated network probe."""
    details: dict[str, Any] = {
        "baseline": spec.compatibility_baseline,
        "platform": current_platform,
        "verified": False,
    }
    if current_platform not in spec.platforms:
        return False, "unsupported-platform", details
    if spec.tool_id == "nexttrace" and current_platform == "windows":
        details["requires_administrator"] = True
        details["administrator"] = _windows_is_admin()
        if not details["administrator"]:
            return False, "windows-administrator-required", details
        details["windivert_runtime"] = _windows_windivert_ready(path)
        if not details["windivert_runtime"]:
            return False, "windows-windivert-runtime-required", details

    if spec.requires_bash_major:
        bash_path = shutil.which(
            "bash", path=trusted_system_environment()["PATH"]
        )
        details["bash_executable"] = Path(bash_path).name if bash_path else None
        if not bash_path:
            return False, f"bash-{spec.requires_bash_major}-required", details
        bash_result = runner([bash_path, "--version"], timeout=10)
        bash_version = _parse_version(
            f"{bash_result.get('stdout', '')}\n{bash_result.get('stderr', '')}"
        )
        details["bash_version"] = ".".join(map(str, bash_version)) if bash_version else None
        if (
            bash_result.get("timed_out")
            or bash_result.get("stdout_truncated")
            or bash_result.get("stderr_truncated")
            or bash_result.get("returncode") != 0
            or not bash_version
            or bash_version[0] < spec.requires_bash_major
        ):
            return False, f"bash-{spec.requires_bash_major}-required", details
        details["bash_path"] = bash_path

    if spec.expected_sha256:
        digest = hashlib.sha256()
        try:
            with Path(path).open("rb") as handle:
                for chunk in iter(lambda: handle.read(65_536), b""):
                    digest.update(chunk)
        except OSError:
            return False, "reviewed-content-unreadable", details
        actual_sha256 = digest.hexdigest()
        details["sha256"] = actual_sha256
        if actual_sha256 != spec.expected_sha256:
            return False, "reviewed-content-hash-mismatch", details

    if spec.version_args:
        version_command = (
            _command_for_script(path, list(spec.version_args))
            if spec.shell_script
            else [path, *spec.version_args]
        )
        result = runner(version_command, timeout=10)
        version_text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
        version = _parse_version(version_text)
        details["version"] = ".".join(map(str, version)) if version else None
        details["version_command_ok"] = (
            result.get("returncode") == 0
            and not result.get("timed_out")
            and not result.get("stdout_truncated")
            and not result.get("stderr_truncated")
        )
        if spec.minimum_version and (
            not details["version_command_ok"]
            or version is None
            or not _version_at_least(version, spec.minimum_version)
        ):
            return False, "version-below-or-unverified-baseline", details
    elif spec.distribution_name and spec.minimum_version:
        try:
            distribution_version = importlib_metadata.version(spec.distribution_name)
        except importlib_metadata.PackageNotFoundError:
            distribution_version = ""
        version = _parse_version(distribution_version)
        details["version"] = distribution_version or None
        details["version_source"] = f"python-distribution:{spec.distribution_name}"
        if version is None or not _version_at_least(version, spec.minimum_version):
            return False, "version-below-or-unverified-baseline", details

    if spec.capability_args:
        capability_command = (
            _command_for_script(path, list(spec.capability_args))
            if spec.shell_script
            else [path, *spec.capability_args]
        )
        result = runner(capability_command, timeout=10)
        output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
        missing = [
            flag for flag in spec.required_capabilities if not _has_capability(output, flag)
        ]
        details["missing_capabilities"] = missing
        if (
            result.get("timed_out")
            or result.get("stdout_truncated")
            or result.get("stderr_truncated")
            or missing
        ):
            return False, "required-capability-unavailable", details

    details["verified"] = True
    return True, "compatible", details


def tool_status(
    selected: Iterable[str] | None = None,
    *,
    include_versions: bool = False,
) -> dict[str, Any]:
    requested = list(dict.fromkeys(selected or tool_ids()))
    unknown = [item for item in requested if item not in TOOL_INDEX]
    if unknown:
        raise ValueError(f"unknown curated tools: {', '.join(unknown)}")
    current = platform_id()
    tools: list[dict[str, Any]] = []
    for tool_id in requested:
        spec = TOOL_INDEX[tool_id]
        path, source = _discover(spec)
        platform_supported = current in spec.platforms
        compatible = platform_supported
        compatibility_checked = False
        compatibility_verified = False
        compatibility_reason = "not-checked"
        compatibility_details: dict[str, Any] = {
            "baseline": spec.compatibility_baseline,
            "platform": current,
            "verified": False,
        }
        if path and platform_supported and include_versions:
            compatibility_checked = True
            compatible, compatibility_reason, compatibility_details = (
                _compatibility_check(
                    spec,
                    path,
                    current,
                    lambda command, **kwargs: _curated_runner(
                        run_command, command, **kwargs
                    ),
                )
            )
            compatibility_verified = compatibility_details.get("verified", False)
        elif path and platform_supported and (
            spec.requires_bash_major or spec.expected_sha256
        ):
            compatibility_checked = True
            compatible, compatibility_reason, compatibility_details = (
                _compatibility_check(
                    spec,
                    path,
                    current,
                    lambda command, **kwargs: _curated_runner(
                        run_command, command, **kwargs
                    ),
                )
            )
            compatibility_verified = compatibility_details.get("verified", False)
        elif spec.tool_id == "nexttrace" and current == "windows":
            compatibility_details["requires_administrator"] = True
            compatibility_details["administrator"] = _windows_is_admin()
            if not compatibility_details["administrator"]:
                compatible = False
                compatibility_reason = "windows-administrator-required"
                compatibility_checked = True
            elif path:
                compatibility_details["windivert_runtime"] = (
                    _windows_windivert_ready(path)
                )
                if not compatibility_details["windivert_runtime"]:
                    compatible = False
                    compatibility_reason = "windows-windivert-runtime-required"
                    compatibility_checked = True
        if not platform_supported:
            compatible = False
            compatibility_reason = "unsupported-platform"
            compatibility_checked = True
        usable = (
            bool(path)
            and platform_supported
            and compatibility_checked
            and compatible
            and compatibility_verified
        )
        record = {
            "tool_id": tool_id,
            "name": spec.name,
            # ``available`` is retained as a compatibility alias for callers,
            # but now means the tool is actually verified usable, not merely
            # that a file with the expected name was found.
            "available": usable,
            "usable": usable,
            "detected": bool(path),
            "platform_supported": platform_supported,
            "compatible": compatible if compatibility_checked else None,
            "compatibility_checked": compatibility_checked,
            "compatibility_verified": compatibility_verified,
            "compatibility_reason": compatibility_reason,
            "compatibility_details": compatibility_details,
            "platform": current,
            "source": source,
            "executable": Path(path).name if path else None,
            "env_var": spec.env_var,
            "compatibility_baseline": spec.compatibility_baseline,
            "install_hint_zh": spec.install_hint_zh,
        }
        tools.append(record)
    return {
        "catalog_version": CATALOG_VERSION,
        "last_verified": LAST_VERIFIED,
        "platform": current,
        "tools": tools,
    }


def _json_value(text: str) -> Any | None:
    if not text.strip():
        return None
    try:
        return parse_json_strict(text)
    except (TypeError, ValueError):
        return None


def _read_json_file(path: Path, limit: int = 1_000_000) -> Any | None:
    try:
        return load_json_limited(path, max_bytes=limit)
    except (OSError, TypeError, UnicodeError, ValueError):
        return None


def _testssl_summary(value: Any) -> dict[str, Any]:
    findings = value
    if isinstance(value, dict):
        findings = value.get("scanResult", [])
    if not isinstance(findings, list):
        return {"structured_output": value}
    severity_counts: dict[str, int] = {}
    selected: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "unknown").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if severity not in {"OK", "INFO"} and len(selected) < 30:
            selected.append(
                {
                    key: item.get(key)
                    for key in ("id", "severity", "finding", "cve", "cwe")
                    if item.get(key) not in (None, "")
                }
            )
    return {
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "notable_findings": selected,
        "notable_findings_truncated": len(selected) == 30,
    }


def _dns_metrics(text: str) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    loss = re.search(
        r"(\d+) requests transmitted,\s*(\d+) responses received,\s*([\d.]+)% lost",
        text,
    )
    if loss:
        metrics.update(
            {
                "requests": int(loss.group(1)),
                "responses": int(loss.group(2)),
                "loss_percent": float(loss.group(3)),
            }
        )
    latency = re.search(
        r"min=([\d.]+)\s*ms,\s*avg=([\d.]+)\s*ms,\s*max=([\d.]+)\s*ms,\s*stddev=([\d.]+)\s*ms",
        text,
    )
    if latency:
        metrics.update(
            {
                "min_ms": float(latency.group(1)),
                "avg_ms": float(latency.group(2)),
                "max_ms": float(latency.group(3)),
                "jitter_ms": float(latency.group(4)),
            }
        )
    rcodes = re.findall(
        r"(?im)\btime=[\d.]+\s*ms\s+([A-Z][A-Z0-9_]*)\b",
        text,
    )
    if rcodes:
        counts: dict[str, int] = {}
        for rcode in rcodes:
            counts[rcode] = counts.get(rcode, 0) + 1
        metrics["rcode_counts"] = counts
    return metrics


def _iperf_metrics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    end = value.get("end") or {}
    summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
    metrics: dict[str, Any] = {}
    for source, destination in (
        ("bits_per_second", "bits_per_second"),
        ("jitter_ms", "jitter_ms"),
        ("lost_percent", "loss_percent"),
        ("seconds", "seconds"),
    ):
        if source in summary:
            metrics[destination] = summary[source]
    return metrics


def _numeric(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().rstrip("%"))
        except ValueError:
            return None
    return None


def _mtr_metrics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    report = value.get("report")
    hubs = report.get("hubs") if isinstance(report, dict) else None
    if not isinstance(hubs, list) or not hubs:
        return {}
    terminal = hubs[-1] if isinstance(hubs[-1], dict) else {}
    metrics: dict[str, Any] = {"hop_count": len(hubs)}
    aliases = {
        "Loss%": "loss_percent",
        "loss": "loss_percent",
        "Avg": "avg_ms",
        "avg": "avg_ms",
        "Wrst": "max_ms",
        "worst": "max_ms",
        "StDev": "jitter_ms",
        "stdev": "jitter_ms",
    }
    for source, destination in aliases.items():
        value_item = _numeric(terminal.get(source))
        if value_item is not None:
            metrics[destination] = value_item
    return metrics


def _mtr_target_reached(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    report = value.get("report")
    if not isinstance(report, dict):
        return False
    metadata = report.get("mtr")
    hubs = report.get("hubs")
    if not isinstance(metadata, dict) or not isinstance(hubs, list) or not hubs:
        return False
    terminal = hubs[-1]
    if not isinstance(terminal, dict):
        return False
    destination = str(metadata.get("dst") or "").strip().strip("[]").casefold()
    terminal_host = str(terminal.get("host") or "").strip().strip("[]").casefold()
    if not destination or not terminal_host:
        return False
    try:
        destination = str(ipaddress.ip_address(destination))
        terminal_host = str(ipaddress.ip_address(terminal_host))
    except ValueError:
        pass
    return destination == terminal_host


def _nexttrace_hops(value: Any) -> list[Any]:
    if isinstance(value, dict):
        hops = value.get("hops")
        if isinstance(hops, list):
            return hops
        trace = value.get("trace")
        if isinstance(trace, dict) and isinstance(trace.get("hops"), list):
            return trace["hops"]
    return []


def _format_host_port(target: str, port: int) -> str:
    candidate = target[1:-1] if target.startswith("[") and target.endswith("]") else target
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return f"{target}:{port}"
    if address.version == 6:
        return f"[{address.compressed}]:{port}"
    return f"{address.compressed}:{port}"


def _command_for_script(path: str, arguments: list[str]) -> list[str]:
    if os.access(path, os.X_OK):
        return [path, *arguments]
    return ["bash", path, *arguments]


def _base_evidence(spec: ToolSpec, path: str, result: dict[str, Any]) -> dict[str, Any]:
    truncated = bool(
        result.get("stdout_truncated") or result.get("stderr_truncated")
    )
    return {
        "tool": spec.name,
        "tool_id": spec.tool_id,
        "official_url": spec.official_url,
        "license": spec.license,
        "last_verified": LAST_VERIFIED,
        "compatibility_baseline": spec.compatibility_baseline,
        "executable": Path(path).name,
        "returncode": result.get("returncode"),
        "timed_out": result.get("timed_out", False),
        "stdout_truncated": result.get("stdout_truncated", False),
        "stderr_truncated": result.get("stderr_truncated", False),
        "execution_status": (
            "failed"
            if result.get("returncode") != 0 or result.get("timed_out")
            else "incomplete"
            if truncated
            else "succeeded"
        ),
    }


def _status_for(result: dict[str, Any], structured: Any | None = None) -> str:
    if result.get("timed_out") or result.get("returncode") not in (0,):
        return "failed"
    if result.get("stdout_truncated") or result.get("stderr_truncated"):
        return "unknown"
    if structured is None:
        return "unknown"
    return "unknown"


def _structured_stdout(result: dict[str, Any]) -> Any | None:
    if result.get("stdout_truncated") or result.get("stderr_truncated"):
        return None
    return _json_value(result.get("stdout", ""))


def _run_mtr(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    command = [path, "--json", "--report", "--report-cycles", "5", "--no-dns"]
    if context["protocol"] == "tcp":
        command.extend(["--tcp", "--port", str(context["port"])])
    else:
        command.extend(["--udp", "--port", str(context["port"])])
    command.append(context["target"])
    result = runner(command, timeout=spec.default_timeout)
    structured = _structured_stdout(result)
    evidence = _base_evidence(spec, path, result)
    evidence["result"] = structured
    metrics = _mtr_metrics(structured)
    evidence["usable_result"] = bool(metrics)
    evidence["target_reached"] = _mtr_target_reached(structured)
    evidence["compatibility"] = context.get("compatibility")
    if structured is None:
        evidence["stdout"] = result["stdout"]
    evidence["stderr"] = result["stderr"]
    status = _status_for(result, structured)
    terminal_loss = metrics.get("loss_percent")
    extreme_latency = (
        isinstance(metrics.get("avg_ms"), (int, float))
        and metrics["avg_ms"] >= EXTREME_AVERAGE_LATENCY_MS
    ) or (
        isinstance(metrics.get("max_ms"), (int, float))
        and metrics["max_ms"] >= EXTREME_MAXIMUM_LATENCY_MS
    )
    if (
        status != "failed"
        and not result.get("stdout_truncated")
        and not result.get("stderr_truncated")
        and metrics
    ):
        if isinstance(terminal_loss, (int, float)) and terminal_loss > 0:
            status = "failed"
            evidence["health_interpretation"] = "terminal-packet-loss-observed"
        elif extreme_latency:
            status = "failed"
            evidence["health_interpretation"] = "extreme-terminal-latency-observed"
        elif terminal_loss == 0 and evidence["target_reached"]:
            status = "ok"
            evidence["health_interpretation"] = "terminal-probes-returned-without-loss"
        else:
            status = "unknown"
            evidence["health_interpretation"] = "declared-destination-not-confirmed"
    return _observation(
        spec, context, result, status, evidence, extra_metrics=metrics
    )


def _run_nexttrace(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    command = [
        path,
        "--json",
        "--no-color",
        "--no-rdns",
        "--data-provider",
        "disable-geoip",
        "--queries",
        "3",
        "--parallel-requests",
        "3",
        "--max-hops",
        "30",
    ]
    if context["protocol"] == "tcp":
        command.extend(["--tcp", "--port", str(context["port"])])
    else:
        command.extend(["--udp", "--port", str(context["port"])])
    command.append(context["target"])
    result = runner(command, timeout=spec.default_timeout)
    structured = _structured_stdout(result)
    evidence = _base_evidence(spec, path, result)
    evidence["result"] = structured
    hops = _nexttrace_hops(structured)
    evidence["usable_result"] = bool(hops)
    evidence["compatibility"] = context.get("compatibility")
    if structured is None:
        evidence["stdout"] = result["stdout"]
    evidence["stderr"] = result["stderr"]
    return _observation(spec, context, result, _status_for(result, structured), evidence)


def _run_dnsdiag(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    command = [path, "-c", "5"]
    if context["protocol"] == "tcp":
        command.append("--tcp")
    command.extend(
        ["-s", context["resolver"], "-p", str(context["port"]), context["target"]]
    )
    result = runner(command, timeout=spec.default_timeout)
    metrics = (
        {}
        if result.get("stdout_truncated") or result.get("stderr_truncated")
        else _dns_metrics(result["stdout"])
    )
    evidence = _base_evidence(spec, path, result)
    evidence.update(
        {
            "resolver": context["resolver"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "usable_result": bool(metrics),
            "compatibility": context.get("compatibility"),
        }
    )
    status = _status_for(result, metrics or None)
    if (
        status != "failed"
        and not result.get("stdout_truncated")
        and not result.get("stderr_truncated")
        and metrics
    ):
        loss = metrics.get("loss_percent")
        responses = metrics.get("responses")
        rcode_counts = metrics.get("rcode_counts")
        parsed_rcodes = (
            sum(rcode_counts.values()) if isinstance(rcode_counts, dict) else 0
        )
        error_rcodes = (
            sorted(set(rcode_counts) - {"NOERROR", "NXDOMAIN"})
            if isinstance(rcode_counts, dict)
            else []
        )
        extreme_latency = (
            isinstance(metrics.get("avg_ms"), (int, float))
            and metrics["avg_ms"] >= EXTREME_AVERAGE_LATENCY_MS
        ) or (
            isinstance(metrics.get("max_ms"), (int, float))
            and metrics["max_ms"] >= EXTREME_MAXIMUM_LATENCY_MS
        )
        if error_rcodes:
            status = "failed"
            evidence["health_interpretation"] = "dns-error-response-observed"
            evidence["error_rcodes"] = error_rcodes
        elif (isinstance(loss, (int, float)) and loss > 0) or responses == 0:
            status = "failed"
            evidence["health_interpretation"] = "dns-packet-loss-observed"
        elif extreme_latency:
            status = "failed"
            evidence["health_interpretation"] = "extreme-dns-latency-observed"
        elif (
            loss == 0
            and isinstance(responses, int)
            and responses > 0
            and parsed_rcodes == responses
            and isinstance(rcode_counts, dict)
            and set(rcode_counts) == {"NOERROR"}
        ):
            status = "ok"
            evidence["health_interpretation"] = "dns-responses-returned-without-loss"
        else:
            status = "unknown"
            evidence["health_interpretation"] = "dns-response-semantics-incomplete"
    return _observation(spec, context, result, status, evidence, extra_metrics=metrics)


def _run_testssl(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    with tempfile.TemporaryDirectory(prefix="netops-testssl-") as temporary:
        output = Path(temporary) / "result.json"
        arguments = [
            "--quiet",
            "--warnings",
            "batch",
            "--color",
            "0",
            "--protocols",
            "--server-defaults",
            "--jsonfile",
            str(output),
            _format_host_port(context["target"], context["port"]),
        ]
        result = runner(
            _command_for_script(path, arguments), timeout=spec.default_timeout
        )
        structured = _read_json_file(output)
    evidence = _base_evidence(spec, path, result)
    summary = _testssl_summary(structured) if structured is not None else None
    evidence["summary"] = summary
    evidence["usable_result"] = structured is not None
    evidence["compatibility"] = context.get("compatibility")
    evidence["stderr"] = result["stderr"]
    if structured is None:
        evidence["stdout"] = result["stdout"]
    status = _status_for(result, structured)
    if (
        status != "failed"
        and not result.get("stdout_truncated")
        and not result.get("stderr_truncated")
        and summary
    ):
        counts = summary.get("severity_counts") or {}
        if any(counts.get(level, 0) for level in ("CRITICAL", "HIGH", "FATAL")):
            status = "failed"
        elif summary.get("finding_count") and set(counts).issubset({"OK", "INFO"}):
            status = "ok"
    return _observation(spec, context, result, status, evidence)


def _run_ipquality(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    with tempfile.TemporaryDirectory(prefix="netops-ipquality-") as temporary:
        output = Path(temporary) / "result.json"
        arguments = ["-p", "-n", "-j", "-o", str(output)]
        result = runner(
            [context["compatibility"]["bash_path"], path, *arguments],
            timeout=spec.default_timeout,
        )
        structured = _read_json_file(output)
    evidence = _base_evidence(spec, path, result)
    evidence["result"] = structured
    evidence["usable_result"] = structured is not None
    evidence["compatibility"] = context.get("compatibility")
    evidence["stderr"] = result["stderr"]
    if structured is None:
        evidence["stdout"] = result["stdout"]
    status = _status_for(result, structured)
    return _observation(spec, context, result, status, evidence)


def _run_iperf3(
    spec: ToolSpec,
    path: str,
    context: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
) -> Observation:
    command = [
        path,
        "--client",
        context["target"],
        "--port",
        str(context["port"]),
        "--time",
        "5",
        "--bitrate",
        "10M" if context["protocol"] == "tcp" else "5M",
        "--connect-timeout",
        "3000",
        "--json",
    ]
    if context["protocol"] == "udp":
        command.append("--udp")
    result = runner(command, timeout=spec.default_timeout)
    structured = _structured_stdout(result)
    evidence = _base_evidence(spec, path, result)
    evidence["result"] = structured
    metrics = _iperf_metrics(structured)
    evidence["usable_result"] = bool(metrics)
    evidence["compatibility"] = context.get("compatibility")
    if structured is None:
        evidence["stdout"] = result["stdout"]
    evidence["stderr"] = result["stderr"]
    return _observation(
        spec,
        context,
        result,
        "failed"
        if isinstance(structured, dict) and structured.get("error")
        else _status_for(result, structured),
        evidence,
        extra_metrics=metrics,
    )


RUNNERS = {
    "mtr": _run_mtr,
    "nexttrace": _run_nexttrace,
    "dnsdiag": _run_dnsdiag,
    "testssl": _run_testssl,
    "ipquality": _run_ipquality,
    "iperf3": _run_iperf3,
}


def _observation(
    spec: ToolSpec,
    context: dict[str, Any],
    result: dict[str, Any],
    status: str,
    evidence: dict[str, Any],
    *,
    extra_metrics: dict[str, Any] | None = None,
) -> Observation:
    segments = {
        "route": "access-network",
        "dns": "dns",
        "tls": "node-ingress",
        "ip-quality": "public-egress",
        "performance": "access-network",
    }
    return Observation(
        vantage_point="local",
        segment=segments[spec.category],
        probe=f"curated-tool:{spec.tool_id}",
        status=status,
        target=context.get("target"),
        protocol=context.get("protocol"),
        metrics={
            "duration_ms": result.get("duration_ms", 0),
            **(extra_metrics or {}),
        },
        evidence=evidence,
        confidence=spec.confidence,
        limitations=list(spec.limitations),
    )


def _missing_observation(
    spec: ToolSpec,
    context: dict[str, Any],
    source: str,
    compatibility: dict[str, Any] | None = None,
) -> Observation:
    segments = {
        "route": "access-network",
        "dns": "dns",
        "tls": "node-ingress",
        "ip-quality": "public-egress",
        "performance": "access-network",
    }
    return Observation(
        vantage_point="local",
        segment=segments[spec.category],
        probe=f"curated-tool:{spec.tool_id}",
        status="unknown",
        target=context.get("target"),
        protocol=context.get("protocol"),
        evidence={
            "tool": spec.name,
            "tool_id": spec.tool_id,
            "available": False,
            "source": source,
            "install_hint_zh": spec.install_hint_zh,
            "official_url": spec.official_url,
            "compatibility_baseline": spec.compatibility_baseline,
            "compatibility": compatibility,
        },
        confidence="high",
        limitations=[
            (
                "工具版本、能力或运行权限未达到兼容基线，已阻止网络探测"
                if source.startswith("incompatible:")
                else "工具未安装、平台不支持或显式路径无效"
            ),
            *spec.limitations,
        ],
    )


def run_curated_tools(
    selected: Iterable[str],
    *,
    mode: str,
    external: bool,
    allow_load: bool = False,
    target: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    resolver: str | None = None,
    tls: bool = False,
    runner: Callable[..., dict[str, Any]] = run_command,
) -> list[Observation]:
    requested = list(dict.fromkeys(selected))
    unknown = [item for item in requested if item not in TOOL_INDEX]
    if unknown:
        raise ValueError(f"unknown curated tools: {', '.join(unknown)}")
    if len(requested) > 1:
        raise ValueError("select exactly one curated tool per scan")
    if requested and not external:
        raise PermissionError("curated tools require explicit --external consent")
    current = platform_id()
    context = {
        "mode": mode,
        "target": target,
        "port": port,
        "protocol": protocol,
        "resolver": resolver,
        "tls": tls,
    }
    for label, value in (("target", target), ("resolver", resolver)):
        if value is not None:
            _validate_network_argument(value, label=label)
    observations: list[Observation] = []
    safe_runner = lambda command, **kwargs: _curated_runner(
        runner, command, **kwargs
    )
    for tool_id in requested:
        spec = TOOL_INDEX[tool_id]
        if mode not in spec.modes:
            raise ValueError(f"tool {tool_id} is not compatible with scan mode {mode}")
        if current not in spec.platforms:
            observations.append(_missing_observation(spec, context, "unsupported-platform"))
            continue
        if spec.load_class == "high" and not allow_load:
            raise PermissionError(f"tool {tool_id} requires explicit --allow-load consent")
        if mode == "node" and (not target or port is None or not protocol):
            raise ValueError(f"tool {tool_id} requires a declared target, port, and protocol")
        if port is not None and (
            type(port) is not int or not 1 <= port <= 65_535
        ):
            raise ValueError("port must be between 1 and 65535")
        if tool_id == "dnsdiag" and not resolver:
            raise ValueError("dnsdiag requires --resolver; NetOps will not choose a public DNS")
        if tool_id == "testssl" and not tls:
            raise ValueError("testssl requires --tls because it audits a TLS service")
        if tool_id == "testssl" and protocol != "tcp":
            raise ValueError("testssl requires --protocol tcp")
        path, source = _discover(spec)
        if not path:
            observations.append(_missing_observation(spec, context, source))
            continue
        compatible, reason, details = _compatibility_check(
            spec, path, current, safe_runner
        )
        if not compatible:
            observations.append(
                _missing_observation(
                    spec,
                    context,
                    f"incompatible:{reason}",
                    details,
                )
            )
            continue
        execution_context = {**context, "compatibility": details}
        observations.append(
            RUNNERS[tool_id](spec, path, execution_context, safe_runner)
        )
    return observations
