# 安全搭建与变更手册

## 安全与授权引用

- 控制通道依赖、`allow`/`warn` 判定、知情同意阶梯、独立远端 SSH 事务和精确计划自动回滚合同，只以 [`control-channel-safety.md`](control-channel-safety.md) 为准。
- 目标是否脱离当前 Agent 路径，只按 [`independence-protocol.md`](independence-protocol.md) 的证据阶梯判定。
- 唯一最终执行卡、执行卡 ID、三个授权选择和范围变化后的授权失效，只以 [`guided-dialogue.md`](guided-dialogue.md) 为准。

本手册不再定义上述门禁或执行合同；下文只补充搭建与配置审计所需的领域细节。

## 变更前的领域审计

- 读取实时服务、监听、路由、防火墙、DNS、3x-ui 数据库和生成后的 Xray 配置。
- 建立旧节点入口、客户端身份、路由规则、出站和实际出口基线。
- 确认特殊 IP 是 VPS 网卡地址还是带认证的上游代理。
- 声明不变量和回滚触发条件。

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
- 上游只提供 IPv4 时，在对应 outbound 顶层显式设置 `targetStrategy: UseIPv4`；该策略不得扩散到其他 outbound 或宿主机。
- HY2 入口能承载 TCP 请求，不代表 SOCKS 上游支持 UDP 目标。使用这类上游前必须单独测试 UDP ASSOCIATE，并明确记录仅 TCP 可用的边界。
- 新旧节点都必须做端到端出口验证。

## 入站

- 在现有入站增加客户端和新建独立入站是两种需求。
- 新建独立入站前检查端口、TCP/UDP、证书/Reality 身份和防火墙。
- 不把上游出口 IP 当成 VPS 本机可监听地址。
- 通过 3x-ui 增加客户端时，同步维护其标准客户端关系与流量记录，并用面板展示、生成配置和真实认证共同验证；不能只改一份临时 Xray JSON。

## 双栈

- 先确认用户需要自动双栈还是确定地址族。
- 需要确定性时，IPv4 节点名只提供 A，IPv6 节点名只提供 AAAA。
- TLS 节点使用分离域名时，证书 SAN 必须覆盖客户端实际连接的每个 IPv4/IPv6 节点名。
- 分别验证解析、入口、出口和客户端支持；不能用 IPv4 成功推断 IPv6 正常。

## 验证

1. 配置/数据库完整性。
2. 当前二进制的配置测试。
3. 服务和监听。
4. 新入口和新出口。
5. 所有受影响旧入口和旧出口。
6. 面板、订阅和流量统计的第二次观察。
7. 将验证结果交回 [`control-channel-safety.md`](control-channel-safety.md) 定义的失败回滚、回执和自动回滚解除流程；本手册不重复定义这些门禁。

本机控制面操作按 [`guided-dialogue.md`](guided-dialogue.md) 和 [`control-channel-safety.md`](control-channel-safety.md) 的固定格式执行；已经失联时转入 [`emergency-recovery.md`](emergency-recovery.md)。
