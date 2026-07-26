# 安全搭建与变更手册

## 执行边界

目标是与当前 Codex 路径无关的 VPS、且不修改本机网络时，允许 Codex 在影响确认后直接 SSH 执行。Codex 负责远端备份、Linux 命令、配置检查、新旧路径验证和失败回滚，不要求用户手动复制命令。

`netopsctl change apply` 和 `change rollback` 是精确文件事务与共享路径自动回滚工具，不是所有 SSH 写入的唯一入口。选择该执行器时，必须同时满足：最终计划未过期、15 分钟内的控制通道证据与计划一致且门禁为 `allow`、用户明确授权同一个计划 ID、目标文件有精确前态校验与备份覆盖、回滚可执行，并为本次运行创建新的持久回执。缺少 `--authorized` 时会在读取计划或连接 SSH 前拒绝。

## 直接 SSH 事务合同

规范条文只有一处：[`control-channel-safety.md`](control-channel-safety.md) 的「独立远端 SSH 事务」八步。不要在本文件复述它，也不要凭记忆改写它。

目标是否独立按 [`independence-protocol.md`](independence-protocol.md) 的证据阶梯判定，不采信远端输出中的自述。

## 变更事务合同

- 使用精确计划或目标可能承载 Codex 流量时，先按 [`control-channel-safety.md`](control-channel-safety.md) 确认依赖；共享控制通道未知时停止在计划阶段。独立远端 VPS 不因此被禁止直接 SSH。
- 读取实时服务、监听、路由、防火墙、DNS、3x-ui 数据库和生成后的 Xray 配置。
- 建立旧节点入口、客户端身份、路由规则、出站和实际出口基线。
- 确认特殊 IP 是 VPS 网卡地址还是带认证的上游代理。
- 声明不变量和回滚触发条件。
- 自动回滚只接受计划执行前已存在的精确文件目标：目标和 `backup_paths` 必须逐项一致。普通文件使用 `file-sha256` 绑定完整内容与元数据；持续写入统计数据的 SQLite 文件可使用 `sqlite-query-sha256`，以只读、确定排序的 `SELECT` 结果绑定稳定配置状态，并以不含 mtime 的稳定元数据摘要防止权限、所有权、ACL、xattr 或 SELinux context 漂移。父目录覆盖不能证明新建文件可恢复。
- SQLite 目标的备份使用 Python 标准库 `sqlite3.Connection.backup` 在线生成一致快照，并在归档前执行 `PRAGMA integrity_check` 和已审核查询复验；不能用运行中的数据库文件直接 `cp` 代替。首次写入前仍会重新执行稳定查询，配置状态发生变化时停止；未纳入查询的流量计数变化不会造成误判。
- 示例 spec 里的全零/全一摘要只是占位符，不能直接执行。普通文件内容摘要使用 `sha256sum`；`metadata_sha256` 由远端 `python3` 标准库按固定 JSON 结构计算，字段包括文件类型、uid/gid、权限模式、纳秒级 mtime，以及按名称排序后以 Base64 表示的全部 xattr。Linux POSIX ACL 与 SELinux context 作为系统 xattr 一并绑定。缺少 Python 3、GNU tar/cp/stat，SQLite 目标缺少标准库 `sqlite3`，或任一 xattr 无法完整读取时停止，不要求用户 SSH 安装额外依赖，也不降级成“只备份内容”。
- “精确元数据恢复”在合同中明确指 uid/gid、权限模式、纳秒级 mtime、POSIX ACL、全部可读取 xattr 与 SELinux context；不承诺恢复 atime、ctime、文件系统 inode flags 或硬链接拓扑，因此 live target 的硬链接计数必须为 1。
- `command` 字段仍是经审核的受信任 Shell，不是执行器沙箱。`affected_paths` 是审核合同与恢复范围，无法从技术上阻止 Shell 写到未声明路径；必须逐字审核所有 apply/validate/verify/rollback 命令，不能把合同描述成“自动约束所有远端写入”。
- 独立通道必须实际验证。共享远端路径只有在计划回滚合同完整时才能执行；执行器必须在首次写入前实际确认 timer 为 active，计划中的 timer 字段本身不是证据。

## 节点专属出口

```text
节点入口或客户端身份
  -> 精确路由规则
  -> 唯一 outbound tag
  -> VPS 原生出口或认证 SOCKS/HTTP 上游
```

- 不修改宿主机默认路由。
- 精确规则放在宽泛规则之前。
- 上游域名解析策略要写入该 outbound，不要借机修改整机 DNS。
- 新旧节点都必须做端到端出口验证。

## 入站

- 在现有入站增加客户端和新建独立入站是两种需求。
- 新建独立入站前检查端口、TCP/UDP、证书/Reality 身份和防火墙。
- 不把上游出口 IP 当成 VPS 本机可监听地址。

## 双栈

- 先确认用户需要自动双栈还是确定地址族。
- 需要确定性时，IPv4 节点名只提供 A，IPv6 节点名只提供 AAAA。
- 分别验证解析、入口、出口和客户端支持；不能用 IPv4 成功推断 IPv6 正常。

## 验证

1. 配置/数据库完整性。
2. 当前二进制的配置测试。
3. 服务和监听。
4. 新入口和新出口。
5. 所有受影响旧入口和旧出口。
6. 面板、订阅和流量统计的第二次观察。
7. 失败时恢复备份并重新验证旧状态。
8. 新旧路径和 Codex 联网都通过后，才解除自动回滚。

人工切换本地网络、代理或 TUN 时，每次只指导一个动作，并同时给出目的、预期结果、异常处理和撤销方式。发生失联后先按 [`emergency-recovery.md`](emergency-recovery.md) 恢复控制通道，不继续追加配置修改。

## 执行与手动远端恢复的当前证据

`change apply` 需要 15 分钟内采集、且 `control_channel` 与计划完全一致的证据。`change rollback` 还需要原 apply 回执、计划绑定的备份目录、同一个计划 ID、显式回滚授权，并且当前证据必须证明独立通道：

```json
{
  "observed_at": "2026-07-20T12:00:00Z",
  "control_channel": {
    "dependency": "independent",
    "change_surfaces": ["remote-proxy-service"],
    "continuity_strategy": "independent-path",
    "target_independence_verified": true,
    "independent_path_verified": true,
    "operator_recovery_reviewed": true,
    "host_reboot_planned": false,
    "evidence": ["provider console path verified independently"]
  }
}
```

计划中的 plan ID 只绑定预期变更；真实恢复还必须使用 apply 回执里的 execution ID、备份目录和完整性摘要。回滚前重新验证现场、控制通道、回执和备份真实性，不允许仅凭目录名猜测。
