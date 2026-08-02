# NetOps

[English](README.md) · **简体中文**

开源社区：[LINUX DO](https://linux.do)

VPS 网络出问题时，真正麻烦的往往不是少了一条命令，而是不知道问题出在哪一段：是电脑、家里的网络、VPS、代理配置、上游出口，还是目标网站本身？

NetOps 就是用来查这件事的。它包含一组通用的 Agent Skills（Claude Code、Codex 或其他兼容 Agent Skills 的工具都能用，下文统称 Agent），以及一个只依赖 Python 标准库的诊断工具。你可以直接用中文描述问题，也可以在命令行里运行扫描。

它的做事顺序很简单：**先扫描，再判断；先保护 Agent 的联网通道，再改网络。** 对不承载当前 Agent 流量、也不修改本机网络的 VPS，确认影响后由 Agent 直接通过 SSH 完成备份、修改、验证和失败回滚，不要求用户手动复制 Linux 命令。

## 什么时候适合用

下面这些情况都可以从 NetOps 开始：

- 节点刚连上正常，用一会儿却全部超时。
- 同一个节点在两台设备上的表现不一样。
- 直连能打开网站，换成代理出口后却超时或被拒绝。
- 3x-ui 面板突然打不开，但其他网站正常。
- 开了 TUN，仍然怀疑 DNS 或 IPv6 绕过代理。
- 新买了一个 SOCKS/HTTP 出口，只想让某个节点使用，不想改变整台 VPS 的默认出口。
- 想搭建 VLESS Reality、Hysteria2、TLS 或双栈节点，又不希望影响已有节点。
- 偶发故障很难复现，想提前保存正常基线和故障时段记录。

NetOps 不会因为某个地区、运营商或网站名称就直接套用结论。它会先确认设备、接入方式、地址族、协议、入口、出口和目标，再根据证据缩小范围。

## 它会检查什么

一次代理连接大致会经过这些位置：

```text
你的电脑 -> 本地网络 -> VPS 入站 -> 代理路由 -> 上游出口 -> 目标网站
```

NetOps 会从当前能够访问的观察点收集信息：

| 位置 | 主要检查内容 |
| --- | --- |
| 客户端 | 系统、活动网卡、默认路由、DNS、TUN 痕迹、IPv4/IPv6 |
| VPS | 资源占用、系统时间、路由、策略路由、防火墙、监听端口和服务状态 |
| 代理节点 | 域名解析、TCP/UDP 连通、TLS 握手、HTTP 响应和各步骤耗时 |
| 3x-ui/Xray | 版本、服务状态和常见配置文件是否存在；变更前再核对入站、出站和路由 |
| 专项工具 | 按问题选择 MTR、NextTrace、dnsdiag、testssl.sh、IPQuality 或 iperf3，不会默认全部运行 |
| 两台设备对比 | 在目标、协议和时间窗口一致时比较两份诊断结果 |

运营商和代理服务商的内部网络通常无法完全看见。报告会把这类区段标成“无法观测”，不会拿一次 traceroute 或 ASN 查询冒充完整线路图。

## 最简单的用法

### 方式一：作为 Agent Skill 使用

需要 Node.js 22.20.0 或更高版本。从已审查的精确发布标签安装。不要把浮动分支或 `latest` 管道直接交给 shell；下面的 CLI 版本和 NetOps 标签都固定。安装器在 Agent 环境中可能自动进入非交互模式，因此先用只读列表确认恰好发现 `netops` 和五个子 Skill，再单独执行安装：

```bash
git clone --branch v0.5.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -l --full-depth
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -g --agent codex --full-depth --skill '*'
```

装给 Claude Code 就把 `--agent codex` 换成 `--agent claude-code`；想一次装给本机全部已识别的 Agent 用 `--agent '*'`。Skill 内容本身与 Agent 无关，同一份规则在哪个 Agent 里都成立。

发布者尚未创建 `v0.5.1` 标签时，这条命令应当失败；不要退回 `main` 或自动选择最新提交。

安装后，直接描述你遇到的情况即可。例如：

```text
先只读扫描这台电脑和我的 VPS，看看节点为什么偶尔断连。

比较这两台电脑的诊断包，确认问题发生在哪一段。

帮我规划一个新的 VLESS Reality 入站，旧节点和 VPS 默认出口都不能改变。

给这个节点生成故障监控调度审查计划，不安装任务。
```

你不需要先弄懂所有术语。如果一句话里还缺少关键条件，NetOps 会给出少量带解释的选项：

```text
目前还不知道问题在客户端还是服务器，先选一个观察范围：

1. 当前设备（推荐）：先做本机只读扫描，不会连接或修改 VPS。
2. VPS：检查服务、监听、路由和资源，需要确认 SSH 授权。
3. 节点全链路：同时收集客户端、VPS 和目标站证据，耗时更长但归因更完整。
```

每轮最多出现 3 个问题，每题只有 2 到 3 个选项。推荐项会放在前面，每个选项都会说明接下来做什么、有什么限制。能自动扫描出来的信息不会反过来让你猜；你的目标已经明确时，也不会强制弹出菜单。

如果信息不够，NetOps 会优先建议只读扫描。需要改服务器时，它会先说明准备改什么、不会改什么、预计中断多久、失败有什么影响，以及怎样备份、验证和回滚。独立远端 VPS 可以在确认后由 Agent 直接 SSH 执行；高风险精确文件事务或共享远端路径可以改用不可变计划和自动回滚。两种方式都只问一次 `执行 / 只保留方案 / 取消`，不会把远端命令甩给用户手动完成。

## 修网络时，怎样避免 Agent 自己掉线

很多人使用 Agent 时本来就开着代理。如果 Agent 正在经过某个代理应用、TUN、节点或 VPS，而修复操作恰好要重启它，Agent 可能和网络一起断开，后面的验证和回滚也无法继续。

NetOps 会把这件事当作所有流程共同遵守的底层安全门：

1. 先确认 Agent 当前经过哪些代理、TUN、节点和 VPS。
2. 对照本次准备修改的组件，判断两条路径是否重合。
3. 目标是另一台不承载当前流量的 VPS、且不改变本机网络时，确认后由 Agent 直接 SSH 执行。
4. 目标与当前节点或 VPS 重合时，优先切到真正独立的网络、代理进程或设备。
5. 共享远端路径在回滚合同完整时可以直接执行；执行器会在首次写入前确认自动回滚 timer 已启动，并在新旧路径验证通过后解除。合同不完整时门禁不会拒绝，而是给出 `warn`：先展示影响、恢复路径、残余风险和更安全的替代方案，用户明确接受本次残余风险后才继续。
6. 本机 TUN、系统代理、活动代理进程、DNS、路由或防火墙切换等可能让 Agent 当场失联的动作，默认交给用户手动完成；远端 Linux 命令仍由 Agent 执行。用户在看过恢复卡后明确要求 Agent 代劳时，这类动作会一次只做一步。

同一个代理软件里的“备用节点”通常不算独立通道，因为重启软件或 TUN 时所有节点会一起中断。手机热点、另一台设备、独立代理进程或提前验证过的服务商控制台更可靠。

如果已经失联，先不要删除配置或反复重装。关闭测试中的 TUN/失效系统代理，切换到已知可用的独立网络，恢复普通 HTTPS 后重新打开 Agent，再把变更摘要或计划 ID、备份位置和最后一步交给它继续处理。完整步骤见 [`references/control-channel-safety.md`](references/control-channel-safety.md)。

### 方式二：直接运行命令行工具

需要 Python 3.10 到 3.14：

```bash
git clone --branch v0.5.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
cd NetOps
python3 scripts/netopsctl.py --help
```

这里同样要求 `v0.5.1` 标签真实存在；标签缺失时应停止，不要改用 `main` 或浮动版本。

`0.3.0` 将变更 spec/plan 合同升级为 `schema_version: "3.0"`，并开放受控远程执行：计划、控制通道门禁、精确文件备份、自动回滚和回执保持绑定。`0.2.0` 的 `2.0` 变更计划会被明确拒绝，必须重新审计和生成。fleet 与诊断包公共合同仍为 `2.0`；监控本地配置/所有权清单以及支持包容器各自的内部 `1.0` 格式不受这次变更影响。

扫描当前电脑：

```bash
python3 scripts/netopsctl.py scan client --output client.json
```

在任何网络变更前，可以先做控制通道初步判断。例如，下面表示 Agent 已经通过一条不经过待修改服务的独立管理路径完成实测：

```bash
python3 scripts/netopsctl.py safety assess \
  --dependency independent \
  --surface remote-proxy-service \
  --strategy independent-path \
  --target-independence-verified \
  --recovery-reviewed \
  --evidence "target confirmed off the current path"
```

输出中的 `guard.decision` 只有 `allow` 和 `warn` 两种取值，本版本不再返回 `block`。`can_apply` 为 `true` 表示控制通道审核已经允许进入执行确认，仍不等于用户授权；`can_apply` 为 `false` 时看 `acknowledgment_required` 与 `can_apply_with_acknowledgment`：后者为 `true` 说明用户在看过风险卡后明确接受残余风险即可继续。`execution_mode` 会明确区分 `direct-ssh-or-plan`、`exact-plan`、`manual-local-control-plane` 和 `read-only`；`execution_available: true` 只说明精确计划执行器已发布。`manual-local-control-plane` 是知情同意也无法交给远端执行器的一类，本机控制面切换仍由用户完成。`change apply` 必须同时提供 `--authorized`、完整的 `--confirm-plan-id` 和 15 分钟内的 `--current-control-channel`；它会重新检查计划时效、主机信息、备份覆盖和门禁结果。只写“可以手动恢复”不能绕过共享路径条件。

审核 spec 后先生成计划；向用户展示计划 ID 和影响卡并获得明确授权，再执行同一个计划：

```bash
netopsctl change plan --spec change-spec.json --fleet fleet.json --output change-plan.json
netopsctl change apply \
  --plan change-plan.json \
  --fleet fleet.json \
  --current-control-channel current-control-channel.json \
  --confirm-plan-id <审核过的完整计划ID> \
  --authorized \
  --receipt change-apply.receipt.json
```

`current-control-channel.json` 必须只包含 `observed_at` 和与计划完全一致的 `control_channel`，时间不得早于执行前 15 分钟。通过 Skill 工作时该文件由 Agent 根据刚完成的检查生成，不要求用户手写。缺少 `--authorized`、计划 ID 不匹配、计划超过 24 小时、控制通道证据过期或改变、现场文件变化时，精确计划执行器会在首次远程写入前停止。门禁重新计算为 `warn` 时同样会停止，除非本次执行已经加上 `--accept-residual-risk`；`can_apply_with_acknowledgment` 为 `false`（例如涉及本机控制面）时，加了该参数也不会继续。已确认的风险会写入回执的 `acknowledged_risks`。失败后先看回执；状态为 `rollback-pending` 时等待已武装的自动回滚，不要重复应用；状态为 `consent-required` 时表示门禁给出 `warn` 而本次没有提供知情同意，回滚尚未发生。

这条命令会生成两个文件：供程序读取的 `client.json`，以及适合直接阅读的 `client.md`。如果还需要确认公网出口，可以主动加上 `--external`：

```bash
python3 scripts/netopsctl.py scan client --external --output client.json
```

检查一个 HTTPS 目标：

```bash
python3 scripts/netopsctl.py scan node \
  --target example.com \
  --port 443 \
  --tls \
  --http \
  --output node.json
```

### 精选工具

内置扫描回答不了下一步时，NetOps 可以接入六个维护活跃、输出可解析的工具：

| 工具 | 用来查什么 | 默认限制 |
| --- | --- | --- |
| MTR | 持续延迟、抖动和丢包 | 5 轮，只测声明的目标 |
| NextTrace | TCP/UDP 去程快照 | 3 次采样、30 跳，默认关闭第三方 GeoIP |
| dnsdiag | 指定 DNS 的延迟和丢包 | 必须明确提供解析器 |
| testssl.sh | TLS 协议、证书和默认参数 | 聚焦检查，不做批量扫描 |
| IPQuality | 当前出口的信誉与分类线索 | 隐私模式、不安装依赖，但仍会查询多个提供商 |
| iperf3 | 两个自有端点间的受控性能样本 | 5 秒限速，并需单独确认流量测试 |

先检查当前电脑上有哪些工具，不会发起网络探测：

```bash
python3 scripts/netopsctl.py tools list
python3 scripts/netopsctl.py tools status --versions
```

状态中的 `detected` 只表示发现了本地文件；只有版本、参数能力和必要校验全部通过时，`usable`（以及兼容字段 `available`）才会是 `true`。

例如，对一个已声明的 HTTPS 节点增加 5 轮 MTR：

```bash
python3 scripts/netopsctl.py scan node \
  --target example.com --port 443 --protocol tcp --tls \
  --tool mtr --external --output node-mtr.json
```

节点扫描中的 `--external` 表示你同意所选工具向说明过的目标、解析器或服务商发出请求。客户端或本机服务器扫描必须改用独立的 `--tool-external`，这样工具授权不会被误当成公网出口身份查询授权。iperf3 还需要 `--allow-load`；IPQuality 等脚本不会被自动下载，缺失时会给出官方来源和路径设置方法。详细兼容规则见 [`references/curated-tools.md`](references/curated-tools.md)。

比较两份条件一致的节点诊断包：

```bash
python3 scripts/netopsctl.py scan compare left.json right.json --output comparison.json
```

生成不可执行的监控调度审查计划，不写入系统任务。Linux 源码目录通常不满足 root 信任链，系统级计划会明确标为 `blocked`；本地试阅请使用 `--scope user`。输出会包含探测目标和完整本地配置草案，不要把 stdout 当作已脱敏支持包分享：

```bash
python3 scripts/netopsctl.py monitor install \
  --target example.com \
  --port 443 \
  --scope user \
  --dry-run
```

也可以安装成系统命令：

```bash
python3 -m pip install .
netopsctl --help
```

## 报告怎么看

每次扫描都会同时输出 JSON 和中文 Markdown 报告。中文报告按固定顺序整理：

1. 一句话结论
2. 检测到的环境
3. 可观测链路图
4. 异常发生在哪一段
5. 支持结论的证据
6. 当前最值得做的一步
7. 无法观测的部分
8. 给需要深入了解的读者看的解释

先看“异常区段”和“推荐下一步”就够了。延迟高、某一跳丢包或者公网 IP 变化都只是线索，不能单独证明故障原因。

需要把结果交给别人时，导出经过校验的支持包：

```bash
netopsctl bundle export diagnostics/node.json --output node-support.zip
netopsctl bundle inspect node-support.zip --report-output node-support-review.md
```

支持包必须使用 `.zip`；默认移除 IP、域名、IDN、MAC、用户目录、凭据，以及出现在值、主机语境或显式 `*_by_host`/`hosts` 映射中的单标签主机。任意 JSON 单词键无法可靠区分“字段名”和“主机名”，因此动态的主机键映射必须采用上述显式命名；否则导出器会把键当作字段名保留。导出器会用结构化规则和高置信启发式检查拒绝疑似残留凭据，但任何启发式都无法证明任意不透明字符串必然安全；对外分享前仍须人工复核归档内容。归档内 SHA-256 只验证三个成员彼此自洽、未在检查后被静默改写，不是数字签名，也不能证明文件来自哪台设备或哪位操作者。源文件、目标 ZIP、检查报告以及扫描隐式生成的 Markdown 都不会静默覆盖已有文件；若确实要重用文件名，应先人工归档旧证据。只有明确使用 `--include-network-identifiers` 才会保留网络标识。

## 命令速查

安装成系统命令后，上面所有例子都可以直接用 `netopsctl` 入口。

| 命令 | 作用 |
| --- | --- |
| `netopsctl scan client` | 只读扫描当前这台电脑 |
| `netopsctl scan node` | 探测已声明的节点：解析、TCP/UDP、TLS、HTTP 和各步骤耗时 |
| `netopsctl scan server` | 本机或已授权远端 VPS 的状态 |
| `netopsctl scan compare` | 比较两份条件一致的诊断包 |
| `netopsctl tools status` | 本机有哪些精选工具、是否真的可用 |
| `netopsctl safety assess` | 变更前的控制通道判断 |
| `netopsctl change plan` / `apply` / `rollback` | 精确计划执行器 |
| `netopsctl monitor install --dry-run` | 只生成不可执行的调度审查材料 |
| `netopsctl bundle export` / `inspect` | 导出已脱敏支持包，以及它的核对报告 |

## 五个工作流程

日常使用只需要记住总入口 `netops`。它会根据问题选择下面一个主要流程：

| Skill | 负责什么 |
| --- | --- |
| `netops-start` | 解释术语，帮助第一次接触 VPS 的用户确定从哪里开始 |
| `netops-scan` | 扫描客户端、VPS、节点和当前可见的传输路径 |
| `netops-build` | 审计、规划并在明确授权后执行 3x-ui、Xray、节点、DNS、TLS、专属出口或标准变更 |
| `netops-fix` | 诊断断连、超时、TUN、DNS、IPv6 和目标站拒绝等问题 |
| `netops-manage` | 审查监控方案与已有数据，并受控执行备份、升级、安全、容量、舰队标准/漂移和用户生命周期变更；仍不安装调度任务 |

协议说明和具体故障案例放在 `references/` 中，不会因为多了一个网站或运营商就再增加一套 Skill。

## 监控发布边界与数据

本版本不发布调度器安装、停止或删除能力。`monitor install/remove` 只在显式 `--dry-run` 时生成不可执行的审查材料；非 dry-run 无条件拒绝，公开 CLI 和 Python API 都没有可开启执行的授权参数，也不存在环境变量或私有函数旁路。`monitor status` 只检查已有本地文件、权限、生命周期标记和 SHA-256 清单，不调用 systemd、launchd 或 Task Scheduler，因此不能证明真实定时任务存在或正在运行。

隐藏的 `monitor sample` 仅用于继续读取由早期兼容版本正确配置、使用规范绝对路径、私有权限、有效所有权标记和匹配清单的本地状态；它不是新安装入口。此兼容采样每 60 秒做轻量检测、每 15 分钟增加一次本机只读检查，连续失败 3 次后可短时增强采样。长期快照只保存匿名状态、有限数值指标、明确观测点、时间、置信度、限制和受控枚举，不保存探测目标、主机名、原始命令输出、Header 或节点链接。受管数据保留 7 天或最多 200 MB，以先达到的限制为准；不抓取数据包，也不运行 traceroute、信誉查询或带宽测试。

审查材料会展示未来可能使用的原生调度器结构（Linux systemd timer、macOS launchd、Windows Task Scheduler），但不要复制执行其中命令。本版本也不会安装长期高权限自研守护进程。

## 数据和隐私

- 公网 IP 查询只有在明确使用 `--external` 时才会发生。
- 精选外部工具只有在显式指定 `--tool` 及其对应授权参数时才会运行：节点扫描使用 `--external`，客户端和本机服务器扫描使用 `--tool-external`；高流量工具还需要独立授权。
- NetOps 不会通过 `curl | bash` 静默下载浮动版本，也不会让外部脚本自动安装系统依赖。
- 导出的诊断包默认会隐藏 IP、域名、用户目录和疑似凭据。
- 客户端控制通道扫描只保存系统代理是否启用，不保存 PAC URL、代理地址或代理环境变量的值。
- 密码、私钥、节点链接、用户/节点/凭据 UUID、代理账号和 API Token 不应写入仓库或报告。NetOps 自己生成的 `run_id`、`observation_id` 及其证据引用是诊断外键，会保留在本地 JSON 和报告中。
- 公开仓库只提供匿名示例。真实主机资料应放在符合 `schemas/fleet.schema.json` 的私有覆盖仓库中；该 Schema 负责可移植的结构与高置信凭据预检，CLI 加载时还会执行权威的 IDNA、Unicode 类别和完整语义复核，两层都必须通过。
- 扫描只适用于你拥有或明确获准管理的设备。

## NetOps 不会做什么

- 不做无边界端口扫描、密码猜测或未经授权的远程操作。
- 不把“端口能连通”直接解释成 VLESS、Hysteria2 等协议一定正常。
- 不承诺还原运营商和服务商内部无法观测的完整物理线路。
- 不会为了修一个节点，默认改变整台 VPS 的出口或覆盖已有配置。
- 不会未经授权修改远端系统。独立远端 VPS 可由 Agent 直接 SSH 执行；若操作会触碰当前 Agent 路径，则必须先建立独立通道、准备自动回滚保护，或由用户在看过风险卡后明确接受本次残余风险。
- 本版本不会安装、停止或删除本地调度任务；监控 install/remove 只有不可执行的 dry-run 审查材料。
- 不会在 Agent 控制通道未知，或只准备了同一代理应用内的备用节点时，静默重启活动网络路径。这种情况门禁给出 `warn` 而不是拒绝：先展示影响、恢复路径、残余风险和更安全的替代方案，用户针对这一次操作明确同意后才继续，并把已确认的风险写入回执。

## 开发与测试

项目核心只使用 Python 标准库。提交前运行：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py .
python3 scripts/validate_skills.py
python3 scripts/check_install_tree.py .
python3 scripts/release_check.py .
```

发布制品必须经过双构建门禁。先安装项目固定的构建工具，再传入明确的 Unix 时间戳和一个尚不存在的输出目录：

```bash
python3 -m pip install "build==1.3.0" "setuptools==83.0.0"
python3 scripts/reproducible_build.py . --source-date-epoch 1720000000 --output-dir release-dist
python3 scripts/package_smoke.py . --dist-dir release-dist
```

`1720000000` 是 CI 使用的稳定参考值；正式标签发布时应改用标签提交的 committer timestamp，并在发布记录中保存该值。脚本会从同一份净化快照复制两个构建目录，强制核对工具版本，要求两个 wheel 原始字节一致，并在清除 sdist 的 gzip 文件名、构建时间、PAX 时间及本机用户/组信息后要求两个规范化 sdist 的字节一致。只有两项检查都通过，才会创建输出目录；已有文件、目录或符号链接都会被拒绝，脚本不会覆盖它们。随后 `package_smoke.py` 会从最终规范化的 sdist 运行完整测试，并分别安装 wheel 和 sdist 做任意目录烟测。

这个门禁证明的是同一源码快照在同一受控 Python、setuptools、build 和运行环境中的可复现性。它不宣称不同操作系统、不同 GitHub runner 镜像、不同 Python 补丁版本或不同 zlib 版本之间必然得到相同字节；需要长期重建时，还应记录这些版本和最终 SHA-256，或固定发布容器摘要。

CI 覆盖 Python 3.10 到 3.14：每个小版本至少在 Linux 运行，3.10、3.12、3.14 还覆盖 macOS 和 Windows；每个环境都会运行双构建门禁，并从最终规范化制品安装后执行任意目录烟测。平台专属命令使用夹具和命令生成测试验证，不会在 CI 中连接真实 VPS 或修改调度器。

## 版本记录

历次版本的变更、破坏性调整和 schema 升级见 [`CHANGELOG.md`](CHANGELOG.md)。

## 开源许可

NetOps 使用 [MIT License](LICENSE) 开源。

你可以自由使用、修改和分发本项目，也可以用于商业用途，但需要保留原有的版权和许可声明。项目按现状提供，作者不对使用过程中产生的问题承担担保责任。完整条款请查看仓库中的 `LICENSE` 文件。
