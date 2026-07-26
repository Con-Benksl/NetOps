from __future__ import annotations

import html
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

from .models import DiagnosticBundle, Observation


SEGMENT_LABELS = {
    "client-local": "客户端本机",
    "client-network": "客户端网络",
    "access-network": "接入网络",
    "management-path": "SSH 管理路径",
    "dns": "DNS 解析",
    "node-ingress": "节点入口",
    "vps": "VPS 本机",
    "vps-local": "VPS 本机",
    "vps-egress": "VPS 出口",
    "proxy-core-and-egress": "代理内核与出口",
    "proxy-egress": "上游代理出口",
    "public-egress": "公网出口",
    "destination": "目标服务",
    "comparison": "双端对比",
    "control-channel": "Agent 控制通道",
}

STATUS_LABELS = {
    "ok": "正常",
    "observed": "已观测",
    "partially-observed": "部分可见",
    "failed": "异常",
    "unknown": "未知",
}

CONFIDENCE_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

SEVERITY_LABELS = {
    "info": "信息",
    "warning": "警告",
    "error": "错误",
    "critical": "严重",
}


def _md_inline(value: Any, *, limit: int = 2_000) -> str:
    """Render untrusted bundle values as one inert Markdown text fragment."""
    text = "".join(
        " "
        if character in {"\u2028", "\u2029"}
        or unicodedata.category(character) in {"Cc", "Cf"}
        else character
        for character in str(value)
    )
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    text = html.escape(text, quote=False)
    for character in ("\\", "`", "*", "_", "[", "]", "(", ")", "#", "!", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _label(mapping: dict[str, str], value: Any) -> str:
    if value is None:
        return "未知"
    mapped = mapping.get(value, value) if isinstance(value, str) else value
    return _md_inline(mapped)


def _optional_inline(value: Any, *, fallback: str = "未记录") -> str:
    if value is None or value == "":
        return fallback
    return _md_inline(value)


def _summary(bundle: DiagnosticBundle) -> str:
    failed = _failed_observations(bundle)
    if failed:
        first = failed[0]
        segment = _label(SEGMENT_LABELS, first.segment)
        return f"目前检测到异常，最先有直接失败证据的区段是“{segment}”。"
    failed_segments = [
        item
        for item in bundle.path_segments
        if isinstance(item.get("status"), str) and item.get("status") == "failed"
    ]
    if failed_segments:
        segment = _label(SEGMENT_LABELS, failed_segments[0].get("name"))
        return f"路径汇总标记了异常区段“{segment}”，但缺少对应的直接观察。"
    actionable = _actionable_findings(bundle)
    if actionable:
        first = actionable[0]
        title = _md_inline(
            first.get("title", "未命名发现")
            if isinstance(first, dict)
            else "格式异常的诊断发现"
        )
        return f"检测到需要处理的诊断发现：“{title}”。"
    incomplete_segments = _incomplete_segments(bundle)
    if incomplete_segments:
        segment = _label(SEGMENT_LABELS, incomplete_segments[0].get("name"))
        return f"现有检查没有发现明确失败，但“{segment}”仍未完整观测，不能作为正常基线。"
    unknown = [item for item in bundle.observations if item.status == "unknown"]
    if unknown:
        return "现有检查没有发现明确失败，但仍有未安装工具、权限不足或不可观测区段。"
    if not bundle.observations:
        return "本次没有取得可验证观察，不能据此判断网络或服务正常。"
    return "本次已执行的检查均未发现明确异常，但这只代表本次观察窗口。"


def _actionable_findings(bundle: DiagnosticBundle) -> list[Any]:
    """Treat every finding except a valid explicit info item as actionable."""

    actionable = [
        item
        for item in bundle.findings
        if not isinstance(item, dict)
        or not isinstance(item.get("severity"), str)
        or item.get("severity") != "info"
    ]
    severity_rank = {"critical": 0, "error": 1, "warning": 2}
    confidence_rank = {"high": 0, "medium": 1, "low": 2}

    def priority(item: Any) -> tuple[int, int]:
        if not isinstance(item, dict):
            return (-1, -1)
        severity = item.get("severity")
        confidence = item.get("confidence")
        if not isinstance(severity, str):
            return (-1, -1)
        return (
            severity_rank.get(severity, -1),
            confidence_rank.get(confidence, 3),
        )

    return sorted(actionable, key=priority)


def _incomplete_segments(bundle: DiagnosticBundle) -> list[dict[str, Any]]:
    return [
        item
        for item in bundle.path_segments
        if isinstance(item, dict)
        and isinstance(item.get("status"), str)
        and item.get("status") in {"unknown", "partially-observed"}
    ]


def _environment_lines(bundle: DiagnosticBundle) -> list[str]:
    lines: list[str] = []
    platform_data = bundle.environment.get("platform") or {}
    if not isinstance(platform_data, dict):
        platform_data = {}
    if platform_data:
        system = platform_data.get("id") or platform_data.get("system") or "未知"
        release = platform_data.get("release") or "未知"
        lines.append(f"- 系统：{_md_inline(system)} {_md_inline(release)}")
    network = bundle.environment.get("network_summary") or {}
    if not isinstance(network, dict):
        network = {}
    if network:
        lines.append(
            "- 地址族：IPv4 "
            + ("存在" if network.get("ipv4_present") else "未确认")
            + "；IPv6 "
            + ("存在" if network.get("ipv6_present") else "未确认")
        )
        hints = _items(network.get("tun_hints"))
        hint_text = ", ".join(_md_inline(item) for item in hints)
        lines.append(f"- TUN/VPN 痕迹：{hint_text if hints else '未检测到明确名称'}")
    host_alias = bundle.environment.get("host_alias")
    if host_alias:
        lines.append(f"- VPS 标识：{_md_inline(host_alias)}")
    if bundle.targets:
        target = bundle.targets[0]
        lines.append(
            f"- 测试目标：{_md_inline(target.get('target'))}:"
            f"{_md_inline(target.get('port'))} / {_md_inline(target.get('protocol'))}"
        )
    curated_tools = bundle.environment.get("curated_tools") or []
    if curated_tools:
        lines.append(
            f"- 精选工具：{', '.join(_md_inline(item) for item in _items(curated_tools))}"
        )
    control_channel = bundle.environment.get("control_channel") or {}
    if not isinstance(control_channel, dict):
        control_channel = {}
    if control_channel:
        proxy_environment = control_channel.get("proxy_environment") or {}
        if not isinstance(proxy_environment, dict):
            proxy_environment = {}
        proxy_env = proxy_environment.get("set_variables", {})
        lines.append(
            "- Agent 控制通道：依赖关系未确认；TUN "
            + ("已检测到" if control_channel.get("tun_detected") else "未确认")
            + "；系统代理 "
            + (
                "已启用"
                if control_channel.get("system_proxy_enabled") is True
                else "未检测到启用"
                if control_channel.get("system_proxy_enabled") is False
                else "未知"
            )
            + "；代理环境变量 "
            + ("存在" if proxy_env else "未检测到")
        )
    if not lines:
        lines.append("- 环境信息不足，报告不会据此猜测运营商、地区或接入方式。")
    return lines


def _path_table(bundle: DiagnosticBundle) -> list[str]:
    lines = [
        "| 区段 | 状态 | 观察点 | 观测时间 | 置信度 | 限制与证据 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    if not bundle.path_segments:
        lines.append(
            "| 未生成 | 未知 | 未记录 | 未记录 | 未知 | 当前模式没有足够路径数据 |"
        )
        return lines
    for segment in bundle.path_segments:
        limitations = _items(segment.get("limitations"))
        evidence = _items(segment.get("evidence"))
        vantage_points = _items(segment.get("vantage_points"))
        vantage_text = (
            "、".join(_md_inline(item) for item in vantage_points)
            if vantage_points
            else "未记录"
        )
        details: list[str] = []
        if limitations:
            details.append(
                "限制：" + "；".join(_md_inline(item) for item in limitations)
            )
        if evidence:
            details.append(
                "证据 ID：" + ", ".join(_md_inline(item) for item in evidence)
            )
        note = "；".join(details) if details else "本次只获得部分状态"
        lines.append(
            f"| {_label(SEGMENT_LABELS, segment.get('name'))} | "
            f"{_label(STATUS_LABELS, segment.get('status'))} | {vantage_text} | "
            f"{_optional_inline(segment.get('observed_at'))} | "
            f"{_label(CONFIDENCE_LABELS, segment.get('confidence'))} | {note} |"
        )
    return lines


def _failed_observations(bundle: DiagnosticBundle) -> list[Observation]:
    failed = [item for item in bundle.observations if item.status == "failed"]

    def sort_key(item: Observation) -> datetime:
        try:
            parsed = datetime.fromisoformat(item.observed_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("observation timestamp has no timezone")
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            # The validated bundle contract requires an offset-aware timestamp.
            # Direct callers with malformed in-memory objects sort last without
            # turning report rendering into a second schema validator.
            return datetime.max.replace(tzinfo=timezone.utc)

    return sorted(failed, key=sort_key)


def _metric_summary(metrics: dict[str, Any]) -> str:
    labels = (
        ("http_status", "HTTP"),
        ("loss_percent", "丢包"),
        ("avg_ms", "平均延迟"),
        ("max_ms", "最大延迟"),
        ("bits_per_second", "吞吐 bit/s"),
    )
    parts: list[str] = []
    for key, label in labels:
        value = metrics.get(key)
        if value is None:
            continue
        suffix = "%" if key == "loss_percent" else " ms" if key.endswith("_ms") else ""
        parts.append(f"{label} {_md_inline(value)}{suffix}")
    return "，".join(parts)


def _evidence_lines(bundle: DiagnosticBundle) -> list[str]:
    failed = _failed_observations(bundle)
    selected = failed[:3]
    curated = [
        item
        for item in bundle.observations
        if item.probe.startswith("curated-tool:")
    ]
    if selected:
        selected.extend(item for item in curated if item not in selected)
        selected = selected[:3]
    else:
        remaining = [
            item
            for item in bundle.observations
            if item.status in {"ok", "unknown"} and item not in curated
        ]
        selected = [*curated[:2], *remaining][:3]
    if not selected:
        return ["- 没有可用观察。"]
    lines: list[str] = []
    for item in selected:
        duration = item.metrics.get("duration_ms")
        duration_text = f"，耗时 {_md_inline(duration)} ms" if duration is not None else ""
        metric_text = _metric_summary(item.metrics)
        metric_suffix = f"，{metric_text}" if metric_text else ""
        lines.append(
            f"- {_md_inline(item.observed_at)}：{_label(SEGMENT_LABELS, item.segment)} / "
            f"{_md_inline(item.probe)} = {_label(STATUS_LABELS, item.status)}"
            f"{duration_text}{metric_suffix}；观察点 {_optional_inline(item.vantage_point)}，"
            f"目标 {_optional_inline(item.target)}，协议 {_optional_inline(item.protocol)}，"
            f"地址族 {_optional_inline(item.address_family)}，"
            f"置信度 {_label(CONFIDENCE_LABELS, item.confidence)}。"
        )
    return lines


def _finding_lines(bundle: DiagnosticBundle) -> list[str]:
    if not bundle.findings:
        return ["- 没有额外诊断发现。"]
    lines: list[str] = []
    for finding in bundle.findings:
        severity = _label(SEVERITY_LABELS, finding.get("severity") or "info")
        segment = _label(SEGMENT_LABELS, finding.get("segment"))
        title = _md_inline(finding.get("title") or "未命名发现")
        confidence = _label(CONFIDENCE_LABELS, finding.get("confidence"))
        evidence = _items(finding.get("evidence"))
        evidence_text = (
            f"；证据 ID：{', '.join(_md_inline(item) for item in evidence[:5])}"
            if evidence
            else ""
        )
        lines.append(
            f"- [{severity}] {segment}：{title}；置信度 {confidence}{evidence_text}。"
        )
    return lines


def _next_step(bundle: DiagnosticBundle) -> str:
    failed = _failed_observations(bundle)
    if failed:
        segment = failed[0].segment
        recommendations = {
            "dns": "固定相同目标和地址族重新查询一次 DNS，并与可正常设备的答案比较。",
            "node-ingress": "从 VPS 本机确认对应 TCP/UDP 监听和防火墙，再做同协议握手测试。",
            "proxy-egress": "从 VPS 原生出口和指定上游出口对同一目标、端口和协议各测试一次。",
            "destination": "保留同一出口，换一个无账号状态的目标进行对照，区分出口链路和目标站策略。",
            "public-egress": "先验证 DNS 和普通 HTTPS，避免把单个公网身份服务失败当成断网。",
            "vps": "先处理服务器上第一项失败的只读检查，再重新扫描，不要同时修改多项配置。",
        }
        return recommendations.get(
            segment,
            "针对第一项失败观察重复一次同目标、同协议测试，确认故障可复现后再修改配置。",
        )
    actionable = _actionable_findings(bundle)
    if actionable:
        first = actionable[0]
        title = (
            first.get("title")
            if isinstance(first, dict) and isinstance(first.get("title"), str)
            else "格式异常的诊断发现"
        )
        return (
            f"先核验并处理第一项诊断发现“{_md_inline(title)}”所引用的证据；"
            "处理前不要把本次结果作为正常基线。"
        )
    incomplete_segments = _incomplete_segments(bundle)
    if incomplete_segments:
        segment = _label(SEGMENT_LABELS, incomplete_segments[0].get("name"))
        return (
            f"补齐“{segment}”缺少的观察点后重新扫描；"
            "在覆盖完整前不要把本次结果作为正常基线。"
        )
    unknown = [item for item in bundle.observations if item.status == "unknown"]
    if unknown:
        missing_tool = next(
            (
                item
                for item in unknown
                if item.probe.startswith("curated-tool:")
                and item.evidence.get("available") is False
            ),
            None,
        )
        if missing_tool:
            return (
                "所选专项工具尚未安装。先继续使用内置扫描；确实需要时，再按报告中的"
                "官方来源和兼容基线审核安装。"
            )
        return "补齐第一项未知观察所缺少的工具或权限，然后重新扫描；暂时不要修改节点配置。"
    if not bundle.observations:
        return "先执行一次有明确观察点的只读扫描；当前空结果不能作为正常基线。"
    return "在发生问题时保留相同目标和协议重新采集一份诊断包，与本次正常基线比较。"


def render_report(bundle: DiagnosticBundle) -> str:
    failed = _failed_observations(bundle)
    failed_segments = [
        item
        for item in bundle.path_segments
        if isinstance(item.get("status"), str) and item.get("status") == "failed"
    ]
    actionable_findings = _actionable_findings(bundle)
    incomplete_segments = _incomplete_segments(bundle)
    abnormal = (
        f"{_label(SEGMENT_LABELS, failed[0].segment)}："
        f"{_md_inline(failed[0].probe)}，置信度 "
        f"{_label(CONFIDENCE_LABELS, failed[0].confidence)}。"
        if failed
        else (
            f"{_label(SEGMENT_LABELS, failed_segments[0].get('name'))}："
            "路径汇总标记异常，但没有对应的直接观察。"
            if failed_segments
            else (
                "诊断发现："
                + _md_inline(
                    actionable_findings[0].get("title", "未命名发现")
                    if isinstance(actionable_findings[0], dict)
                    else "格式异常的诊断发现"
                )
                + "。"
                if actionable_findings
                else (
                    f"{_label(SEGMENT_LABELS, incomplete_segments[0].get('name'))}："
                    "路径仍未完整观测，不能判断是否正常。"
                    if incomplete_segments
                    else (
                        "没有取得可验证观察，不能判断是否正常。"
                        if not bundle.observations
                        else "没有获得直接失败证据。"
                    )
                )
            )
        )
    )
    limitations = list(dict.fromkeys(
        bundle.limitations
        + [
            limitation
            for item in bundle.observations
            for limitation in item.limitations
        ]
    ))
    lines = [
        "# NetOps 诊断报告",
        "",
        "## 一句话结论",
        "",
        _summary(bundle),
        "",
        "## 检测到的环境",
        "",
        *_environment_lines(bundle),
        "",
        "## 可观测链路",
        "",
        *_path_table(bundle),
        "",
        "## 异常区段",
        "",
        abnormal,
        "",
        "## 诊断发现",
        "",
        *_finding_lines(bundle),
        "",
        "## 证据",
        "",
        *_evidence_lines(bundle),
        "",
        "## 推荐下一步",
        "",
        _next_step(bundle),
        "",
        "## 无法观测的部分",
        "",
    ]
    if limitations:
        lines.extend(f"- {_md_inline(item)}" for item in limitations)
    else:
        lines.append("- 本次没有额外限制记录，但仍不能把单点探测当作完整物理线路。")
    lines.extend(
        [
            "",
            "## 进阶解释",
            "",
            "本报告只描述指定时间和观察点取得的证据。运营商、上游代理内部转发、"
            "回程以及目标站未公开的风控决策可能不可见。",
            "",
            f"运行 ID：{_md_inline(bundle.run_id)}；数据模型：{_md_inline(bundle.schema_version)}。",
            "",
        ]
    )
    return "\n".join(lines)
