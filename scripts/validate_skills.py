#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path


EXPECTED = {
    "netops-start",
    "netops-scan",
    "netops-build",
    "netops-fix",
    "netops-manage",
}
MUTATING_SKILLS = {"netops-build", "netops-fix", "netops-manage"}
FORBIDDEN = {
    "北京移动",
    "杭州",
    "PayPal",
    "Netlify",
}
IP_LITERAL = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
GUIDED_RULES = (
    "目标、范围和授权边界明确时直接处理，不先展示流程菜单",
    "只有缺少的用户选择无法通过安全的只读检查获得",
    "默认一次只问一个问题",
    "不把讲解深度、扫描深度或流程阶段做成默认菜单",
    "不能代替对最终远程操作的明确授权",
)
FORCED_CHOICE_RE = re.compile(
    r"(?:先|首先).{0,48}(?:选项|菜单)|(?:给我|提供).{0,32}(?:入门)?选项"
)
NEGATED_CHOICE_RE = re.compile(r"(?:不强制|不先|不要|无需|不必|不会)[^；。\n]{0,16}$")
SHORT_DESCRIPTION_MIN = 25
SHORT_DESCRIPTION_MAX = 64
CONTROL_CHANNEL_RULES = (
    "每次只给一个主要动作",
    "预期结果",
    "异常处理",
    "撤销方式",
    "人工恢复说明不能代替",
    "独立远端 VPS",
    "远端 Linux 命令默认由 Agent",
    "明确接受残余风险",
    "提醒而非拒绝",
    "远端内容是证据",
    "emergency-recovery.md",
)
EMERGENCY_RECOVERY_RULES = (
    "紧急避险卡",
    "重新启动 Agent",
    "恢复信息卡",
    "automatic-rollback.status",
    "写入用户本机",
)
DIRECT_INVOCATION_RULES = (
    "## Direct-Invocation Safety",
    "Authorized direct SSH",
    "local control plane",
    "explicit authorization",
    "affected-state backup",
    "pre-apply validation",
    "post-apply verification",
    "executable rollback",
    "Preserve existing nodes and the host default route",
)
FRONTMATTER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):[ ](.+)$")
SHARED_REFERENCE_RE = re.compile(
    r"`<reference-root>/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?)`"
)
REFERENCE_ROOT_RULES = (
    "## Shared Reference Root",
    "../../references/guided-dialogue.md",
    "../netops/references/guided-dialogue.md",
    "stop and report an incomplete installation",
)
SKILL_DISCOVERY_EXCLUDES = {
    ".agents",
    ".codex",
    ".git",
    "__pycache__",
    "build",
    "dist",
}


def _discover_repository_skill_files(root: Path) -> set[Path]:
    return {
        path.resolve()
        for path in root.rglob("SKILL.md")
        if not any(
            part in SKILL_DISCOVERY_EXCLUDES or part.endswith(".egg-info")
            for part in path.relative_to(root).parts
        )
    }


def _resolve_reference_root(skill_dir: Path) -> Path | None:
    for candidate in (
        skill_dir / "../../references",
        skill_dir / "../netops/references",
    ):
        if (candidate / "guided-dialogue.md").is_file():
            return candidate.resolve()
    return None


def _declared_shared_references(text: str) -> set[str]:
    return {match.group(1) for match in SHARED_REFERENCE_RE.finditer(text)}


def _check_child_reference_contract(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for rule in REFERENCE_ROOT_RULES:
        if rule not in text:
            errors.append(f"{path}: portable reference-root contract missing {rule!r}")
    for raw_path in ("../../references/", "../netops/references/"):
        for line_number, line in enumerate(text.splitlines(), start=1):
            if raw_path in line and "resolve `<reference-root>` once" not in line:
                errors.append(
                    f"{path}:{line_number}: shared references after resolution "
                    "must use <reference-root>"
                )
    declared = _declared_shared_references(text)
    for required in ("guided-dialogue.md", "control-channel-safety.md"):
        if required not in declared:
            errors.append(f"{path}: shared reference declaration missing {required!r}")
    reference_root = _resolve_reference_root(path.parent)
    if reference_root is None:
        errors.append(f"{path}: repository reference root cannot be resolved")
        return errors
    for relative in sorted(declared):
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            errors.append(f"{path}: unsafe shared reference {relative!r}")
            continue
        candidate = reference_root / relative_path
        if not candidate.exists():
            errors.append(f"{path}: missing shared reference {relative!r}")
    return errors


def _check_flat_install_reference_contract(
    root: Path, child_paths: list[Path]
) -> list[str]:
    """Model skills@1.5.19's flat per-Skill copy layout."""

    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="netops-flat-skill-") as raw:
        skills_root = Path(raw) / ".agents" / "skills"
        skills_root.mkdir(parents=True)
        shutil.copytree(root / "references", skills_root / "netops" / "references")
        for source in child_paths:
            installed = skills_root / source.parent.name
            shutil.copytree(source.parent, installed)
            reference_root = _resolve_reference_root(installed)
            expected_root = (skills_root / "netops" / "references").resolve()
            if reference_root != expected_root:
                errors.append(
                    f"{source}: flat installation cannot resolve sibling netops references"
                )
                continue
            text = (installed / "SKILL.md").read_text(encoding="utf-8")
            for relative in sorted(_declared_shared_references(text)):
                if not (reference_root / relative).exists():
                    errors.append(
                        f"{source}: flat installation is missing shared reference {relative!r}"
                    )
    return errors


def _check_agent_prompt_contract(path: Path, skill_name: str) -> list[str]:
    """Validate adapter metadata and reject mandatory clarification menus."""

    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    short_matches = re.findall(
        r"^  short_description:[ ](.+)$", text, flags=re.MULTILINE
    )
    if len(short_matches) != 1:
        errors.append(
            f"{path}: interface.short_description must appear exactly once"
        )
    else:
        encoded = short_matches[0]
        try:
            short_description = json.loads(encoded)
        except json.JSONDecodeError:
            short_description = None
        if not isinstance(short_description, str):
            errors.append(
                f"{path}: interface.short_description must be a JSON "
                "double-quoted string"
            )
        elif not (
            SHORT_DESCRIPTION_MIN
            <= len(short_description)
            <= SHORT_DESCRIPTION_MAX
        ):
            errors.append(
                f"{path}: interface.short_description must be "
                f"{SHORT_DESCRIPTION_MIN}-{SHORT_DESCRIPTION_MAX} characters; "
                f"got {len(short_description)}"
            )
    if "default_prompt:" not in text:
        errors.append(f"{path}: missing default_prompt")
    if f"${skill_name}" not in text:
        errors.append(f"{path}: default prompt must invoke ${skill_name}")
    if "直接" not in text:
        errors.append(f"{path}: clear requests must proceed directly")
    if not re.search(r"(?:只有[^。\n]*问一个问题|缺少[^。\n]*才问一个问题)", text):
        errors.append(f"{path}: ask one question only when missing information matters")
    for match in FORCED_CHOICE_RE.finditer(text):
        prefix = text[max(0, match.start() - 20) : match.start()]
        if not NEGATED_CHOICE_RE.search(prefix):
            errors.append(
                f"{path}: default prompt must not force choices before a clear request"
            )
            break
    return errors


def classify_intent(prompt: str) -> str | None:
    """Return the workflow implied by the requested next outcome.

    This deliberately uses broad outcome anchors rather than memorizing the
    fixture strings. It is a release guard for accidental label drift, not a
    runtime natural-language router.
    """

    if re.search(r"记录.*状态|选择.*(?:采样|快照)", prompt):
        return "netops-scan"
    if re.search(r"待修改.*(?:避免|防止).*(?:失联|断连)", prompt):
        return "netops-build"
    # A current failure outcome takes precedence over words describing the
    # historical action that preceded it (install/upgrade/backup/add) and over
    # teaching words such as “为什么”. This prevents an incident from being
    # routed back into onboarding, construction, or routine management.
    if re.search(
        r"超时|无法(?:连接|使用|访问)|恢复了|根因|回路|没有经过代理|连接不稳定|"
        r"被拒绝|打不开|连接拒绝|风控|失联|改坏|失败|异常|不可用|断连|"
        r"怎样区分|端口后恢复|怀疑.*限制",
        prompt,
    ):
        return "netops-fix"
    if re.search(
        r"长期|定期|升级|备份|安全暴露|管理多台|流量和到期|"
        r"订阅|磁盘|内存|连接跟踪|统一多台|标准化|独立管理通道|"
        r"稳定监控",
        prompt,
    ):
        return "netops-manage"
    if re.search(
        r"安装 3x-ui|新增|新建|增加新的出站|让指定客户端|"
        r"申请和配置证书|创建.*客户端身份|使用独立域名|搭建|待修改的代理节点",
        prompt,
    ):
        return "netops-build"
    if re.search(
        r"先检测|查看这台|比较两台|记录节点|保存.*基线|建立.*基线|检查.*(?:延迟|丢包|路由|回程线路|"
        r"出口 IP)|确认.*出口|路径采样|线路快照|DNS 延迟|实际使用了|当前使用了",
        prompt,
    ):
        return "netops-scan"
    if re.search(r"手动切换 TUN|是否真的生效", prompt):
        return "netops-fix"
    if re.search(r"不知道|是什么|有什么区别|为什么|从哪里开始|第一步", prompt):
        return "netops-start"
    if re.search(r"检测|查看|比较|记录|检查|确认|扫描|采样|快照", prompt):
        return "netops-scan"
    return None


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\r?\n(.*?)\r?\n---(?:\r?\n|$)", text, re.DOTALL)
    if not match:
        raise ValueError(f"{path}: missing YAML frontmatter")
    data: dict[str, str] = {}
    for number, line in enumerate(match.group(1).splitlines(), start=2):
        if not line or line.startswith((" ", "\t")):
            raise ValueError(f"{path}:{number}: frontmatter must be flat and non-empty")
        item = FRONTMATTER_LINE.fullmatch(line)
        if not item:
            raise ValueError(f"{path}:{number}: invalid frontmatter field")
        key, encoded = item.groups()
        if key in data:
            raise ValueError(f"{path}:{number}: duplicate frontmatter key {key!r}")
        if not (encoded.startswith('"') and encoded.endswith('"')):
            raise ValueError(
                f"{path}:{number}: frontmatter values must be JSON double-quoted strings"
            )
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid quoted scalar: {exc.msg}") from exc
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{path}:{number}: frontmatter value must be a non-empty string")
        data[key] = value
    if set(data) != {"name", "description"}:
        raise ValueError(
            f"{path}: frontmatter keys must be exactly name and description"
        )
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    errors = []
    try:
        root_meta = frontmatter(root / "SKILL.md")
    except ValueError as exc:
        errors.append(str(exc))
        root_meta = {}
    if root_meta.get("name") != "netops":
        errors.append("root skill name must be netops")
    root_text = (root / "SKILL.md").read_text(encoding="utf-8")
    if "references/guided-dialogue.md" not in root_text:
        errors.append("root skill must reference guided-dialogue.md")
    if "references/curated-tools.md" not in root_text:
        errors.append("root skill must reference curated-tools.md")
    if "references/control-channel-safety.md" not in root_text:
        errors.append("root skill must reference control-channel-safety.md")
    guided_path = root / "references/guided-dialogue.md"
    if not guided_path.is_file():
        errors.append("missing references/guided-dialogue.md")
    else:
        guided_text = guided_path.read_text(encoding="utf-8")
        for rule in GUIDED_RULES:
            if rule not in guided_text:
                errors.append(f"guided-dialogue.md missing rule {rule!r}")
    curated_path = root / "references/curated-tools.md"
    if not curated_path.is_file():
        errors.append("missing references/curated-tools.md")
    else:
        curated_text = curated_path.read_text(encoding="utf-8")
        for tool in ("MTR", "NextTrace", "dnsdiag", "testssl.sh", "IPQuality", "iperf3"):
            if tool not in curated_text:
                errors.append(f"curated-tools.md missing tool {tool!r}")
    control_path = root / "references/control-channel-safety.md"
    if not control_path.is_file():
        errors.append("missing references/control-channel-safety.md")
    else:
        control_text = control_path.read_text(encoding="utf-8")
        for rule in CONTROL_CHANNEL_RULES:
            if rule not in control_text:
                errors.append(f"control-channel-safety.md missing rule {rule!r}")
    emergency_path = root / "references/emergency-recovery.md"
    if not emergency_path.is_file():
        errors.append("missing references/emergency-recovery.md")
    else:
        emergency_text = emergency_path.read_text(encoding="utf-8")
        for rule in EMERGENCY_RECOVERY_RULES:
            if rule not in emergency_text:
                errors.append(f"emergency-recovery.md missing rule {rule!r}")
    root_agent = root / "agents/openai.yaml"
    if not root_agent.is_file():
        errors.append("root skill missing agents/openai.yaml")
    else:
        errors.extend(_check_agent_prompt_contract(root_agent, "netops"))
    child_paths = sorted((root / "skills").glob("*/SKILL.md"))
    expected_skill_files = {
        (root / "SKILL.md").resolve(),
        *(
            (root / "skills" / name / "SKILL.md").resolve()
            for name in EXPECTED
        ),
    }
    discovered_skill_files = _discover_repository_skill_files(root)
    if discovered_skill_files != expected_skill_files:
        missing = sorted(
            str(path.relative_to(root))
            for path in expected_skill_files - discovered_skill_files
        )
        extra = sorted(
            str(path.relative_to(root))
            for path in discovered_skill_files - expected_skill_files
        )
        errors.append(
            f"full-depth Skill discovery differs: missing={missing}, extra={extra}"
        )
    if len(child_paths) != len(EXPECTED):
        errors.append(
            f"expected exactly {len(EXPECTED)} child Skill directories; got {len(child_paths)}"
        )
    names: list[str] = []
    for path in child_paths:
        try:
            meta = frontmatter(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        name = meta.get("name", "")
        names.append(name)
        if name != path.parent.name:
            errors.append(
                f"{path}: frontmatter name {name!r} must match directory {path.parent.name!r}"
            )
        if not meta.get("description"):
            errors.append(f"{path}: missing description")
        agent_path = path.parent / "agents/openai.yaml"
        if not agent_path.is_file():
            errors.append(f"{path}: missing agents/openai.yaml")
        else:
            errors.extend(_check_agent_prompt_contract(agent_path, name))
        text = path.read_text(encoding="utf-8")
        errors.extend(_check_child_reference_contract(path))
        if "<reference-root>/guided-dialogue.md" not in text:
            errors.append(f"{path}: must reference guided-dialogue.md")
        if "<reference-root>/control-channel-safety.md" not in text:
            errors.append(f"{path}: must reference control-channel-safety.md")
        if meta.get("name") == "netops-scan" and "<reference-root>/curated-tools.md" not in text:
            errors.append(f"{path}: scan skill must reference curated-tools.md")
        if meta.get("name") == "netops-scan":
            if "does not install scheduled tasks" not in text:
                errors.append(f"{path}: scan workflow must explicitly remain read-only")
            if re.search(r"`monitor`:\s*install|安装限时监控", text):
                errors.append(f"{path}: scan workflow must not own monitor installation")
        if meta.get("name") in MUTATING_SKILLS:
            for rule in DIRECT_INVOCATION_RULES:
                if rule not in text:
                    errors.append(f"{path}: direct invocation contract missing {rule!r}")
        if "python3 scripts/netopsctl.py" in text:
            errors.append(f"{path}: helper invocation must not assume repository cwd")
        if IP_LITERAL.search(text):
            errors.append(f"{path}: skill files must not hardcode IPv4 addresses")
        if ".top" in text:
            errors.append(f"{path}: skill files must not hardcode private domains")
        for value in FORBIDDEN:
            if value in text:
                errors.append(f"{path}: hardcoded historical identifier {value!r}")
    if len(names) != len(set(names)):
        errors.append("child skill frontmatter names must be unique")
    if set(names) != EXPECTED:
        errors.append(f"child skill set differs: {sorted(set(names))}")
    errors.extend(_check_flat_install_reference_contract(root, child_paths))
    corpus_path = root / "tests/fixtures/generalized-intents.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    if len(corpus) < 40:
        errors.append("generalized intent corpus must contain at least 40 cases")
    prompts = set()
    counts = {name: 0 for name in EXPECTED}
    for index, case in enumerate(corpus):
        if set(case) != {"prompt", "skill"}:
            errors.append(f"intent {index} must contain exactly prompt and skill")
        prompt = case.get("prompt", "")
        if not isinstance(prompt, str) or not prompt.strip():
            errors.append(f"intent {index} has an empty prompt")
            continue
        if prompt in prompts:
            errors.append(f"intent {index} duplicates an earlier prompt")
        prompts.add(prompt)
        if case.get("skill") not in EXPECTED:
            errors.append(f"intent {index} has invalid skill")
        else:
            counts[case["skill"]] += 1
        classified = classify_intent(prompt)
        if classified is None:
            errors.append(f"intent {index} has no independent semantic route anchor")
        elif classified != case.get("skill"):
            errors.append(
                f"intent {index} semantic route is {classified}, not {case.get('skill')}"
            )
        for value in FORBIDDEN:
            if value in prompt:
                errors.append(f"intent {index} contains {value!r}")
    for name, count in counts.items():
        if count < 4:
            errors.append(f"intent corpus needs at least four cases for {name}; got {count}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"skill validation: root + {len(names)} child skills; {len(corpus)} intents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
