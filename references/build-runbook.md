# 安全搭建与变更手册

## 本版发布边界

本版本只支持只读审计、`safety assess`、变更 spec 校验和 `netopsctl change plan`。`netopsctl change apply`、`netopsctl change rollback` 以及对应的 Python 公共函数都会在读取计划、预留回执或建立 SSH 连接前无条件 fail-closed；没有环境变量、隐藏参数或受支持的代码绕过。下面涉及备份、自动回滚和执行事务的条目是未来执行器的审核合同，不代表本版本已经提供这些能力，也不得据此声称远端备份或回滚已经建立。

## 未来执行器的审核合同（本版不可执行）

- 先按 [`control-channel-safety.md`](control-channel-safety.md) 确认 Codex 是否依赖待修改的代理、TUN、节点或 VPS；控制通道未知时停止在计划阶段。
- 读取实时服务、监听、路由、防火墙、DNS、3x-ui 数据库和生成后的 Xray 配置。
- 建立旧节点入口、客户端身份、路由规则、出站和实际出口基线。
- 确认特殊 IP 是 VPS 网卡地址还是带认证的上游代理。
- 声明不变量和回滚触发条件。
- 自动回滚只接受计划执行前已存在的精确文件目标：目标、`backup_paths` 与类型化 `file-sha256` 预检必须逐项一致；预检值来自同一次只读审计，并绑定内容与 GNU/Linux 元数据摘要。备份、首次写入及恢复都会重新核对这些值；父目录覆盖不能证明新建文件可恢复。
- 示例 spec 里的全零/全一摘要只是占位符，不能直接执行。内容摘要使用 `sha256sum`；`metadata_sha256` 必须按执行器同一顺序，对 GNU `stat -c '%u:%g:%a:%y:%C'`、`getfacl --omit-header --numeric`、`getfattr --absolute-names --dump -m -` 的 `LC_ALL=C` 合并输出计算 SHA-256。缺少 GNU tar/cp/stat、ACL 或 xattr 工具时停止，不降级成“只备份内容”。
- “精确元数据恢复”在合同中明确指 uid/gid、权限模式、纳秒级 mtime、POSIX ACL、全部可读取 xattr 与 SELinux context；不承诺恢复 atime、ctime、文件系统 inode flags 或硬链接拓扑，因此 live target 的硬链接计数必须为 1。
- `command` 字段仍是经审核的受信任 Shell，不是执行器沙箱。`affected_paths` 是审核合同与恢复范围，无法从技术上阻止 Shell 写到未声明路径；必须逐字审核所有 apply/validate/verify/rollback 命令，不能把合同描述成“自动约束所有远端写入”。
- 独立通道必须实际验证；仅在未来执行器重新发布且完成独立安全审查后，才可讨论由工具武装自动回滚。当前版本不能把计划里的 timer 字段解释为 active。

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

人工切换本地网络、代理或 TUN 时，每次只指导一个动作，并同时给出预期结果、异常处理和撤销方式。发生失联后先执行紧急恢复卡，不继续追加配置修改。

## 手动远端恢复材料（本版没有执行入口）

`change rollback` 在本版本无条件拒绝，不会读取以下证据或连接远端。若独立运维人员在工具之外制定恢复方案，应先从服务商控制台、独立 SSH 路径或另一条已验证网络做新的只读核验；下列结构只用于审核材料：

```json
{
  "observed_at": "2026-07-20T12:00:00Z",
  "control_channel": {
    "dependency": "independent",
    "change_surfaces": ["remote-proxy-service"],
    "continuity_strategy": "independent-path",
    "independent_path_verified": true,
    "operator_recovery_reviewed": true,
    "host_reboot_planned": false,
    "evidence": ["provider console path verified independently"]
  }
}
```

计划中出现的 plan ID、host、execution ID、备份目录和摘要字段只能说明审核合同的预期绑定关系；因为本版本不会生成真实 apply 回执或远端备份，不能把这些字段当作可恢复性证明。恢复必须由独立获批的运维流程重新验证现场和备份真实性。
