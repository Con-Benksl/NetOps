from __future__ import annotations

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


def _label(mapping: dict[str, str], value: str | None) -> str:
    if value is None:
        return "未知"
    return mapping.get(value, value)


def _summary(bundle: DiagnosticBundle) -> str:
    failed = [item for item in bundle.observations if item.status == "failed"]
    if failed:
        first = failed[0]
        segment = _label(SEGMENT_LABELS, first.segment)
        return f"目前检测到异常，最先有直接失败证据的区段是“{segment}”。"
    unknown = [item for item in bundle.observations if item.status == "unknown"]
    if unknown:
        return "现有检查没有发现明确失败，但仍有未安装工具、权限不足或不可观测区段。"
    return "本次已执行的检查均未发现明确异常，但这只代表本次观察窗口。"


def _environment_lines(bundle: DiagnosticBundle) -> list[str]:
    lines: list[str] = []
    platform_data = bundle.environment.get("platform") or {}
    if platform_data:
        system = platform_data.get("id") or platform_data.get("system") or "未知"
        release = platform_data.get("release") or "未知"
        lines.append(f"- 系统：{system} {release}")
    network = bundle.environment.get("network_summary") or {}
    if network:
        lines.append(
            "- 地址族：IPv4 "
            + ("存在" if network.get("ipv4_present") else "未确认")
            + "；IPv6 "
            + ("存在" if network.get("ipv6_present") else "未确认")
        )
        hints = network.get("tun_hints") or []
        lines.append(f"- TUN/VPN 痕迹：{', '.join(hints) if hints else '未检测到明确名称'}")
    host_alias = bundle.environment.get("host_alias")
    if host_alias:
        lines.append(f"- VPS 标识：{host_alias}")
    if bundle.targets:
        target = bundle.targets[0]
        lines.append(
            f"- 测试目标：{target.get('target')}:{target.get('port')} / "
            f"{target.get('protocol')}"
        )
    if not lines:
        lines.append("- 环境信息不足，报告不会据此猜测运营商、地区或接入方式。")
    return lines


def _path_table(bundle: DiagnosticBundle) -> list[str]:
    lines = ["| 区段 | 状态 | 说明 |", "| --- | --- | --- |"]
    if not bundle.path_segments:
        lines.append("| 未生成 | 未知 | 当前模式没有足够路径数据 |")
        return lines
    for segment in bundle.path_segments:
        limitations = segment.get("limitations") or []
        evidence = segment.get("evidence") or []
        note = "；".join(limitations) if limitations else (
            "证据：" + ", ".join(evidence) if evidence else "本次只获得部分状态"
        )
        lines.append(
            f"| {_label(SEGMENT_LABELS, segment.get('name'))} | "
            f"{_label(STATUS_LABELS, segment.get('status'))} | {note} |"
        )
    return lines


def _failed_observations(bundle: DiagnosticBundle) -> list[Observation]:
    failed = [item for item in bundle.observations if item.status == "failed"]
    return sorted(failed, key=lambda item: item.observed_at)


def _evidence_lines(bundle: DiagnosticBundle) -> list[str]:
    failed = _failed_observations(bundle)
    selected = failed[:3]
    if not selected:
        selected = [
            item
            for item in bundle.observations
            if item.status in {"ok", "unknown"}
        ][:3]
    if not selected:
        return ["- 没有可用观察。"]
    lines: list[str] = []
    for item in selected:
        duration = item.metrics.get("duration_ms")
        duration_text = f"，耗时 {duration} ms" if duration is not None else ""
        lines.append(
            f"- {item.observed_at}：{_label(SEGMENT_LABELS, item.segment)} / "
            f"{item.probe} = {_label(STATUS_LABELS, item.status)}"
            f"{duration_text}，置信度 {_label(CONFIDENCE_LABELS, item.confidence)}。"
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
    unknown = [item for item in bundle.observations if item.status == "unknown"]
    if unknown:
        return "补齐第一项未知观察所缺少的工具或权限，然后重新扫描；暂时不要修改节点配置。"
    return "在发生问题时保留相同目标和协议重新采集一份诊断包，与本次正常基线比较。"


def render_report(bundle: DiagnosticBundle) -> str:
    failed = _failed_observations(bundle)
    abnormal = (
        f"{_label(SEGMENT_LABELS, failed[0].segment)}："
        f"{failed[0].probe}，置信度 "
        f"{_label(CONFIDENCE_LABELS, failed[0].confidence)}。"
        if failed
        else "没有获得直接失败证据。"
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
        lines.extend(f"- {item}" for item in limitations)
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
            f"运行 ID：`{bundle.run_id}`；数据模型：`{bundle.schema_version}`。",
            "",
        ]
    )
    return "\n".join(lines)
