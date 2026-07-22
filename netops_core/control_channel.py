from __future__ import annotations

import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any

from .redaction import Redactor


DEPENDENCIES = ("independent", "shared", "unknown")
CONTINUITY_STRATEGIES = (
    "independent-path",
    "automatic-rollback",
    "manual-recovery",
)
CHANGE_SURFACES = (
    "local-proxy-app",
    "local-tun",
    "local-dns",
    "local-routes",
    "local-firewall",
    "remote-proxy-service",
    "remote-network",
    "remote-dns",
    "remote-firewall",
    "node-or-vps",
    "unknown",
)
LOCAL_CHANGE_SURFACES = {
    "local-proxy-app",
    "local-tun",
    "local-dns",
    "local-routes",
    "local-firewall",
}
CONTROL_CHANNEL_KEYS = {
    "dependency",
    "change_surfaces",
    "continuity_strategy",
    "independent_path_verified",
    "operator_recovery_reviewed",
    "host_reboot_planned",
    "evidence",
}
ROLLBACK_TIMER_KEYS = {"enabled", "delay_seconds"}
ROLLBACK_CONTRACT_KEYS = {
    "declared_targets",
    "covered_targets",
    "uncovered_targets",
    "preflight_file_targets",
    "preflight_hashes",
    "unverified_targets",
    "inexact_backup_paths",
    "restore_strategy",
    "rollback_operations",
    "minimum_delay_seconds",
    "executable",
}
MAX_ROLLBACK_TARGETS = 64


def _reject_extra_keys(raw: dict[str, Any], allowed: set[str], *, label: str) -> None:
    extras = sorted(set(raw) - allowed)
    if extras:
        raise ValueError(f"{label} contains unsupported fields: {extras}")


def normalize_remote_absolute_path(value: Any, *, label: str) -> str:
    """Return one canonical POSIX absolute path or reject path aliases."""

    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} must be an absolute remote path")
    if value.startswith("//"):
        raise ValueError(f"{label} must use exactly one leading slash")
    if "\\" in value:
        raise ValueError(f"{label} must not contain backslashes")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029"}
        for character in value
    ):
        raise ValueError(f"{label} contains control characters")
    path = PurePosixPath(value)
    if ".." in path.parts:
        raise ValueError(f"{label} must not contain '..'")
    normalized = str(path)
    if normalized != value:
        raise ValueError(f"{label} must be a canonical absolute remote path")
    return normalized


def normalize_control_channel(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("control_channel must be an object")
    _reject_extra_keys(raw, CONTROL_CHANNEL_KEYS, label="control_channel")
    dependency = raw.get("dependency", "unknown")
    if dependency not in DEPENDENCIES:
        raise ValueError(f"control_channel.dependency must be one of {DEPENDENCIES}")
    strategy = raw.get("continuity_strategy", "manual-recovery")
    if strategy not in CONTINUITY_STRATEGIES:
        raise ValueError(
            "control_channel.continuity_strategy must be one of "
            f"{CONTINUITY_STRATEGIES}"
        )
    surfaces = raw.get("change_surfaces", ["unknown"])
    if not isinstance(surfaces, list) or not surfaces:
        raise ValueError("control_channel.change_surfaces must be a non-empty list")
    normalized_surfaces: list[str] = []
    for surface in surfaces:
        if surface not in CHANGE_SURFACES:
            raise ValueError(
                "control_channel.change_surfaces contains unsupported value "
                f"{surface!r}"
            )
        if surface not in normalized_surfaces:
            normalized_surfaces.append(surface)
    for key in (
        "independent_path_verified",
        "operator_recovery_reviewed",
        "host_reboot_planned",
    ):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ValueError(f"control_channel.{key} must be true or false")
    evidence = raw.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) > 20:
        raise ValueError("control_channel.evidence must contain at most 20 entries")
    evidence_redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    for item in evidence:
        if (
            not isinstance(item, str)
            or item != item.strip()
            or not 8 <= len(item) <= 500
            or any(
                unicodedata.category(character) in {"Cc", "Cf"}
                or character in {"\u2028", "\u2029"}
                for character in item
            )
        ):
            raise ValueError(
                "control_channel.evidence entries must be 8..500 printable characters"
            )
        if evidence_redactor.text(item) != item:
            raise ValueError(
                "control_channel.evidence must use a non-secret audit reference"
            )
    return {
        "dependency": dependency,
        "change_surfaces": normalized_surfaces,
        "continuity_strategy": strategy,
        "independent_path_verified": raw.get("independent_path_verified", False),
        "operator_recovery_reviewed": raw.get("operator_recovery_reviewed", False),
        "host_reboot_planned": raw.get("host_reboot_planned", False),
        "evidence": evidence,
    }


def normalize_rollback_timer(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("rollback_timer must be an object")
    _reject_extra_keys(raw, ROLLBACK_TIMER_KEYS, label="rollback_timer")
    enabled = raw.get("enabled", False)
    delay = raw.get("delay_seconds", 600)
    if not isinstance(enabled, bool):
        raise ValueError("rollback_timer.enabled must be true or false")
    if type(delay) is not int or not 120 <= delay <= 3600:
        raise ValueError("rollback_timer.delay_seconds must be 120..3600")
    return {"enabled": enabled, "delay_seconds": delay}


def _normalize_rollback_contract(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("rollback_contract must be an object")
    _reject_extra_keys(raw, ROLLBACK_CONTRACT_KEYS, label="rollback_contract")
    list_fields = (
        "declared_targets",
        "covered_targets",
        "uncovered_targets",
        "preflight_file_targets",
        "unverified_targets",
        "inexact_backup_paths",
    )
    normalized: dict[str, Any] = {}
    for key in list_fields:
        values = raw.get(key)
        if not isinstance(values, list) or len(values) > MAX_ROLLBACK_TARGETS:
            raise ValueError(f"rollback_contract.{key} must contain absolute paths")
        normalized[key] = list(
            dict.fromkeys(
                normalize_remote_absolute_path(
                    item, label=f"rollback_contract.{key}"
                )
                for item in values
            )
        )
    preflight_hashes = raw.get("preflight_hashes")
    if not isinstance(preflight_hashes, list) or len(preflight_hashes) > MAX_ROLLBACK_TARGETS:
        raise ValueError("rollback_contract.preflight_hashes must be a bounded list")
    normalized_hashes: list[dict[str, str]] = []
    seen_hash_targets: set[str] = set()
    for index, item in enumerate(preflight_hashes):
        allowed_keys = {"target", "sha256", "metadata_sha256"}
        if not isinstance(item, dict) or frozenset(item) not in {
            frozenset(allowed_keys),
            frozenset({*allowed_keys, "query"}),
        }:
            raise ValueError(
                f"rollback_contract.preflight_hashes[{index}] is invalid"
            )
        target = normalize_remote_absolute_path(
            item.get("target"),
            label=f"rollback_contract.preflight_hashes[{index}].target",
        )
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(
                f"rollback_contract.preflight_hashes[{index}].sha256 is invalid"
            )
        if target in seen_hash_targets:
            raise ValueError("rollback_contract.preflight_hashes has duplicate targets")
        seen_hash_targets.add(target)
        normalized_hashes.append({"target": target, "sha256": digest})
        metadata_digest = item.get("metadata_sha256")
        if (
            not isinstance(metadata_digest, str)
            or len(metadata_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in metadata_digest
            )
        ):
            raise ValueError(
                f"rollback_contract.preflight_hashes[{index}].metadata_sha256 is invalid"
            )
        normalized_hashes[-1]["metadata_sha256"] = metadata_digest
        if "query" in item:
            query = item.get("query")
            if (
                not isinstance(query, str)
                or not query.strip()
                or len(query) > 16_384
                or not re.match(r"^\s*SELECT\b", query, flags=re.IGNORECASE)
                or any(
                    unicodedata.category(character) in {"Cc", "Cf"}
                    and character not in {"\n", "\t"}
                    for character in query
                )
            ):
                raise ValueError(
                    f"rollback_contract.preflight_hashes[{index}].query is invalid"
                )
            normalized_hashes[-1]["query"] = query
    normalized["preflight_hashes"] = normalized_hashes
    if [item["target"] for item in normalized_hashes] != normalized[
        "preflight_file_targets"
    ]:
        raise ValueError(
            "rollback_contract preflight hashes must match preflight_file_targets"
        )
    rollback_operations = raw.get("rollback_operations")
    if type(rollback_operations) is not int or rollback_operations < 0:
        raise ValueError("rollback_contract.rollback_operations must be non-negative")
    minimum_delay = raw.get("minimum_delay_seconds")
    if type(minimum_delay) is not int or minimum_delay < 1:
        raise ValueError("rollback_contract.minimum_delay_seconds must be positive")
    executable = raw.get("executable")
    if not isinstance(executable, bool):
        raise ValueError("rollback_contract.executable must be true or false")
    restore_strategy = raw.get("restore_strategy")
    if restore_strategy != (
        "exact-existing-files-content-mode-owner-mtime-acl-xattr-selinux"
    ):
        raise ValueError(
            "rollback_contract.restore_strategy must be "
            "exact-existing-files-content-mode-owner-mtime-acl-xattr-selinux"
        )
    normalized.update(
        {
            "restore_strategy": restore_strategy,
            "rollback_operations": rollback_operations,
            "minimum_delay_seconds": minimum_delay,
            "executable": executable,
        }
    )
    return normalized


def emergency_steps(platform_name: str = "unknown") -> list[str]:
    steps = [
        "立即停止继续改配置，不要删除当前代理配置、备份或诊断记录。",
        "先关闭测试中的 TUN 或系统代理；不要先卸载代理软件。",
        "切换到与故障路径无关的网络，例如手机热点或另一条已验证线路。",
        "只启动最后一次确认可用的代理配置，确认普通 HTTPS 可以访问。",
        "重新启动 Codex，并说明刚才执行到哪一步、变更摘要或计划 ID 和备份位置。",
    ]
    if platform_name == "macos":
        steps.insert(
            2,
            "在系统设置的当前网络服务中检查“代理”，关闭仍被启用的网页或 SOCKS 代理。",
        )
    elif platform_name == "windows":
        steps.insert(
            2,
            "在“设置 -> 网络和 Internet -> 代理”中关闭残留的手动系统代理。",
        )
    elif platform_name == "linux":
        steps.insert(
            2,
            "在桌面网络设置中关闭系统代理，并在新终端检查 HTTP_PROXY、HTTPS_PROXY 和 ALL_PROXY。",
        )
    return steps


def assess_control_channel(
    control_channel: dict[str, Any],
    rollback_timer: dict[str, Any],
    *,
    platform_name: str = "unknown",
    rollback_contract: dict[str, Any] | None = None,
    require_independent_path: bool = False,
) -> dict[str, Any]:
    control = normalize_control_channel(control_channel)
    timer = normalize_rollback_timer(rollback_timer)
    contract = _normalize_rollback_contract(rollback_contract)
    reasons: list[str] = []
    can_apply = False
    risk = "blocked"
    execution_mode = "read-only"
    local_surfaces = sorted(set(control["change_surfaces"]) & LOCAL_CHANGE_SURFACES)

    if "unknown" in control["change_surfaces"]:
        reasons.append("尚未明确本次变更会触碰哪些网络组件。")
    elif local_surfaces:
        execution_mode = "manual-local-control-plane"
        reasons.append(
            "本机控制面变更必须由用户手动完成，不能由远端执行器接管："
            + ", ".join(local_surfaces)
        )
    elif control["dependency"] == "unknown":
        reasons.append("尚未确认 Codex 联网是否依赖本次要修改的组件。")
    elif not control["evidence"]:
        reasons.append("尚未提供控制通道依赖与恢复条件的可审核证据。")
    elif not control["operator_recovery_reviewed"]:
        reasons.append("用户尚未看过并确认人工恢复与紧急避险步骤。")
    elif require_independent_path and control["dependency"] != "independent":
        reasons.append(
            "手动远端回滚不能依赖正在恢复的共享路径；请使用已验证独立通道或等待已武装的自动回滚。"
        )
    elif control["dependency"] == "independent":
        if (
            control["continuity_strategy"] == "independent-path"
            and control["independent_path_verified"]
        ):
            can_apply = True
            risk = "guarded"
            execution_mode = "direct-ssh-or-plan"
            reasons.append(
                "已验证目标不在当前 Codex 路径上；可直接 SSH 或使用精确计划执行器。"
            )
        else:
            reasons.append("独立通道尚未通过实际连通性验证。")
    elif control["continuity_strategy"] == "automatic-rollback":
        if control["host_reboot_planned"]:
            reasons.append("一次性 transient timer 不能保护会重启目标主机的变更。")
        elif local_surfaces:
            reasons.append(
                "远端自动回滚不能恢复本机组件：" + ", ".join(local_surfaces)
            )
        elif contract is None:
            reasons.append("尚未提供与本次变更目标绑定的自动回滚合同。")
        elif not contract["declared_targets"]:
            reasons.append("自动回滚合同没有声明实际变更目标。")
        elif contract["rollback_operations"] < 1:
            reasons.append("自动回滚合同没有可执行的 rollback 操作。")
        elif contract["uncovered_targets"]:
            reasons.append(
                "自动回滚合同未覆盖目标："
                + ", ".join(contract["uncovered_targets"])
            )
        elif contract["inexact_backup_paths"]:
            reasons.append(
                "自动回滚只允许逐个精确文件备份，不能用父目录推导可恢复性："
                + ", ".join(contract["inexact_backup_paths"])
            )
        elif contract["unverified_targets"]:
            reasons.append(
                "自动回滚目标缺少 file-sha256 / sqlite-query-sha256 类型化前态校验："
                + ", ".join(contract["unverified_targets"])
            )
        elif not contract["executable"]:
            reasons.append("自动回滚合同未通过可执行性检查。")
        elif not timer["enabled"]:
            reasons.append("选择了自动回滚，但回滚定时器未启用。")
        elif timer["delay_seconds"] < contract["minimum_delay_seconds"]:
            reasons.append(
                f"回滚定时器 {timer['delay_seconds']} 秒短于计划所需的 "
                f"{contract['minimum_delay_seconds']} 秒保护窗口。"
            )
        else:
            can_apply = True
            risk = "guarded-high"
            execution_mode = "exact-plan"
            reasons.append(
                f"执行器必须在首次写入前设置 {timer['delay_seconds']} 秒自动回滚，"
                "并在新旧路径验证通过后解除。"
            )
    elif control["continuity_strategy"] == "independent-path":
        reasons.append("请先切换并验证独立通道，再把依赖状态标记为 independent。")
    else:
        reasons.append(
            "仅靠人工恢复不能保证 Codex 断线后继续；请改用已验证独立通道，"
            "或为远程目标提供完整的自动回滚合同。"
        )

    if execution_mode == "direct-ssh-or-plan":
        next_action = (
            "审核条件满足；展示目标主机、精确 SSH 操作、影响、备份、验证与回滚，"
            "获得明确授权后由 Codex 执行。只有选择精确计划执行器时才要求计划 ID。"
        )
    elif execution_mode == "exact-plan":
        next_action = (
            "审核条件满足；先向用户展示计划 ID、影响、预计中断、验证与回滚方式，"
            "获得该计划 ID 的明确授权后才可执行。"
        )
    elif execution_mode == "manual-local-control-plane":
        next_action = (
            "只让用户手动完成一个本机控制面动作；确认 Codex 仍在线后，"
            "远端 Linux 命令继续由 Codex 执行。"
        )
    elif control["dependency"] == "shared":
        next_action = (
            "优先切换到独立网络或独立代理进程，并补充回滚审核材料；"
            "在控制通道门禁允许前不要执行。"
        )
    else:
        next_action = (
            "先扫描或由用户确认 Codex 当前经过的代理、TUN、节点和 VPS；"
            "控制通道未知时停止在计划阶段。"
        )
    return {
        "decision": "allow" if can_apply else "block",
        "can_apply": can_apply,
        "execution_available": True,
        "execution_mode": execution_mode,
        "risk": risk,
        "reasons": reasons,
        "next_action": next_action,
        "emergency_steps": emergency_steps(platform_name),
    }
