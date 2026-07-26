# 独立性判定协议

本文只回答一个问题：用什么可执行的观测，把 `control_channel.dependency` 从 `unknown` 落到 `independent` 或 `shared`。知情同意阶梯、风险卡内容、四种处置结果和紧急避险步骤见 `control-channel-safety.md`，这里不重复。

先记住三条不对称，否则整条阶梯会被读反：

- 阶梯是按“发现依赖”的速度排序，不是按“证明独立”的强度排序。第 1、2 步命中即可定为 `shared`；未命中只是必要条件，不能把 `unknown` 抬成 `independent`。
- 未命中之所以不能证明独立：存在中转/落地或上游 SOCKS/HTTP 时，你看到的出口属于链路末端，而目标机可能正在链路中间。
- 能正向产出 `independent` 的只有第 3 步，且必须与第 2 步同向。远端自述（面板文字、登录 banner、配置注释、日志）不进入本阶梯。

## 1. 出口 IP 比对

- 征得用户同意后运行 `netopsctl scan client --external --output <bundle>`，取 `public-egress` 观察中的 IP。`--external` 会向外部身份服务商发起 HTTPS 请求，必须先说明再执行。
- 组装目标地址集合：fleet 中该主机的 `management.address`（仅当它本身是 IP 字面量），加上 `domains.ipv4`、`domains.ipv6`、`domains.panel` 里的每个名字逐个解析（`netopsctl scan node --target <名字> --port 443`，读 `getaddrinfo` 观察的 `answers[].address`）。
- `management.address` 是 SSH 别名时不贡献任何地址，必须把它记成覆盖缺口，不能当成“已比对完”。
- 命中集合中任一地址：判定 `shared`，阶梯到此结束。
- 未命中：只能得出“当前出口不是这台机”，目标仍可能是链路中间的中转机，继续第 2 步。
- 目标机自己的出口取不到：`scan server --host` 不接受 `--external`，不要试图远程测目标的出口来补这一步。

## 2. 客户端激活节点比对

- 请用户报出代理应用中当前生效节点的服务器地址。只记地址和端口，不要 UUID、密码或完整节点链接。
- 用 `netopsctl scan node --target <地址> --port <端口>` 解析，与第 1 步的目标地址集合比对。
- 命中：判定 `shared`。
- 未命中：可作为 `independent` 的必要证据，但不足以定级，仍需第 3 步佐证。
- 本步的结论绑定在“当时那个生效节点”上。第 3 步切换之后必须用切换后的生效节点重跑一次，不能沿用切换前的比对结果。
- 应用启用了自动选路、负载均衡或分流规则时，本步只覆盖当前这一次连接，必须在报告里写明这个边界。

## 3. 受控切换测试

唯一能正向证明独立的一步。切换动作属于本机控制面，默认由用户手动完成（见 `control-channel-safety.md` 三条硬规则第 1 条），Codex 只负责测量。

1. 切换前：`netopsctl scan client --external --output before.json`，记下该 `public-egress` 观察的 `observation_id`。
2. 用户在代理应用里切到一个明确不使用目标 VPS 的节点，或直接关闭代理与 TUN。撤销方式：切回原节点。
3. 切换后：`netopsctl scan client --external --output after.json`，同样记下 `observation_id`。

结果如何解读：

- 出口改变：切换前的出口可归因于原节点，原路径为 `shared`。这不代表新路径干净，新节点仍可能链式经过目标机。只有切换后的出口不落在目标地址集合内，且用切换后的生效节点重跑第 2 步同样未命中，才可把当前路径判定为 `independent`。
- 出口不变：可能是目标本来就没承载流量，也可能两个节点共用同一落地。除非第 2 步同向未命中，否则仍是 `unknown`。
- 切换过程中 Codex 断线：这是最强的依赖证据，直接判定 `shared`，并按紧急避险卡先恢复控制通道。
- 两个 `observation_id` 写进诊断包与最终回执。`netopsctl safety assess --evidence` 只写结论句，不要粘贴 UUID：连字符形式的 UUID 会被脱敏规则拦下，报错为 evidence 必须是非秘密审计说明。

## 4. 用户确认

- 用户确认是补充项，用来解释观测、暴露上面几步没覆盖的设备和网络，或者推翻一个 `independent` 判定。
- 它永远不能单独把 `unknown` 抬成 `independent`。小白恰恰是最不清楚哪台机在承载自己流量的人，“这台没在用”不是安全证明。
- 只有一个方向允许它单独定级：用户说“我现在正在用这台”，直接按 `shared` 处理。

## 证据冲突与未知的去向

- 任何一步指向 `shared`，即使其他步指向独立，也按 `shared` 处理；依赖判定取最保守的结果。
- 第 1 步未命中但第 2 步命中：说明链路上存在中转/落地或上游，按 `shared` 处理，并在报告里写明这处矛盾。
- 观测之间时间跨度过大或中途换过网络：作废重测，不要把不同现场的结果拼在一起。
- 走完阶梯仍是 `unknown`：保持 `dependency=unknown`，不要拒绝。按 `control-channel-safety.md` 的知情同意阶梯给出风险卡，用户逐次明确接受残余风险后继续执行，并把已确认的风险写入回执。
