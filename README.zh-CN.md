# NetOps

给 Codex 和命令行使用的 VPS / 代理网络工具：先拿到证据，再做受控修改，
并把备份、验证和回滚放进同一个流程。

[English](README.md) | 简体中文

[![test](https://github.com/Con-Benksl/NetOps/actions/workflows/test.yml/badge.svg)](https://github.com/Con-Benksl/NetOps/actions/workflows/test.yml)
[![GitHub release](https://img.shields.io/github/v/release/Con-Benksl/NetOps?sort=semver)](https://github.com/Con-Benksl/NetOps/releases/latest)
![Python](https://img.shields.io/badge/Python-3.10--3.14-3776AB?logo=python&logoColor=white)
[![MIT License](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

代理节点一出问题，最容易走偏的地方是把现象当成原因。一次超时，可能发生在
客户端、本地网络、DNS、VPS 入站、Xray 路由、上游出口，也可能只是目标网站
拒绝了当前出口。NetOps 会记录每个可见区段能证明什么、不能证明什么，不拿一次
ping、traceroute 或公网 IP 查询直接下结论。

这个仓库包含一套中文优先的 Agent Skills，以及一个只依赖 Python 标准库的
命令行工具。第一次接触 VPS 的用户可以直接把现象告诉 Codex；熟悉运维的人可以
保存 JSON 证据、比较两次观测、导出脱敏支持包，或者执行带备份和回滚的远程事务。

> [!IMPORTANT]
> 只能扫描和管理你拥有或明确获准管理的设备。NetOps 不做无边界端口扫描、
> 凭据尝试、流量截获，也看不到运营商和服务商内部的完整网络。

## 先从这里开始

按你的使用习惯选择入口：

| 入口 | 适合谁 | 环境要求 |
| --- | --- | --- |
| Codex Skills | 想直接描述问题，由 Codex 带着检查和操作 | Node.js 22.20.0 或更高版本 |
| `netopsctl` | 需要可重复命令、JSON、支持包和精确变更计划 | Python 3.10-3.14 |

### 安装 Codex Skills

从审查过的发布标签安装。第一条 `skills` 命令只列出内容，正常结果应当是一个
根 Skill 加五个工作流；第二条才把这六个 Skill 全局安装给 Codex。

```bash
git clone --branch v0.3.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -l --full-depth
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -g --agent codex --full-depth --skill '*'
```

PowerShell 使用同一条 clone 命令，然后运行：

```powershell
$env:NPM_CONFIG_CACHE = Join-Path $env:TEMP "netops-npm-cache"
npx skills@1.5.19 add ./NetOps -l --full-depth
npx skills@1.5.19 add ./NetOps -g --agent codex --full-depth --skill '*'
```

在 Codex 环境中，清单命令开头也可能出现 `installing non-interactively`。
看最后一段即可：显示 `Available Skills` 代表只发现了六个 Skill；第二条命令才会
执行全局复制。

如果标签不存在，就停下来检查，不要悄悄改用 `main`。安装完成后，直接说你要的
结果：

```text
先只读扫描这台电脑和我的 VPS，找出节点从哪一段开始超时。

比较这两个诊断包，告诉我故障时段到底变了什么。

新增一个走专属 SOCKS 出口的 VLESS Reality 入站。已有节点和 VPS 默认路由
都不能改变。

生成监控调度审查计划，但不要安装定时任务。
```

只有缺失信息确实会改变下一步时，NetOps 才会提问。每轮最多三题，每题给出少量
带影响说明的选项。只读扫描能查到的事实，不会再让用户自己猜。

### 直接运行命令行工具

核心包没有 Python 标准库之外的运行时依赖。

```bash
git clone --branch v0.3.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
cd NetOps
python3 -m pip install .
netopsctl --version
netopsctl scan client --output client.json
```

Windows 可以用 `py -3` 代替 `python3`。后面的运维示例使用 POSIX 换行符；
PowerShell 可以把参数写在一行，或把每行末尾的反斜杠改成反引号。

最后一条命令会生成 `client.json` 和便于阅读的 `client.md`。默认不会查询公网
出口；只有明确加上 `--external` 才会访问公网身份服务。两个输出都不会覆盖
已有文件。

## 它怎样判断问题

NetOps 把代理路径拆成可以分别检查的区段：

```mermaid
flowchart LR
    A[客户端] --> B[本地与接入网络]
    B --> C[VPS 入站]
    C --> D[代理内核与路由]
    D --> E[VPS 或上游出口]
    E --> F[目标服务]
```

一次完整流程有四步：

1. 先读环境，不凭一个公网 IP 猜城市、运营商、地址族、协议或出口。
2. 给每个区段记录状态、时间、观察点、证据和限制。
3. 推荐一个能继续区分主要假设的动作，不一次扔出一长串检查清单。
4. 获得变更授权后，保留无关状态，备份目标，修改前校验，修改后同时复测新旧
   行为；关键验证失败就回滚。

运营商或代理服务商内部看不到的区段会明确标成未知。一次 traceroute 不是完整
物理线路图。

## 能做什么

| 范围 | 命令或 Skill | 实际行为 |
| --- | --- | --- |
| 客户端检查 | `netopsctl scan client` | 读取网卡、路由、DNS、TUN 痕迹、系统代理和 IPv4/IPv6 状态 |
| VPS 检查 | `netopsctl scan server` | 在本机或获准的 SSH 会话中读取资源、时间、路由、策略路由、防火墙、监听和服务 |
| 节点检查 | `netopsctl scan node` | 对一个声明过的目标执行有界 DNS、TCP/UDP、TLS、HTTP、代理或外部工具检查 |
| 前后对比 | `netopsctl scan compare` | 只比较目标、协议、配置和时间窗口兼容的两份观测 |
| 外部工具 | `netopsctl tools` | 发现并核对 MTR、NextTrace、dnsdiag、testssl.sh、IPQuality 和 iperf3 的实际能力 |
| 支持包 | `netopsctl bundle` | 导出和检查经过脱敏、带校验和的 ZIP |
| 控制通道 | `netopsctl safety assess` | 判断拟议变更会不会切断当前 Codex |
| 远程事务 | `netopsctl change` | 固化计划、绑定前态、执行获准的精确变更并保存回滚回执 |
| 监控审查 | `netopsctl monitor` | 生成不可执行的调度审查材料，检查受管本地文件；不会安装或删除任务 |

常见场景包括：节点间歇性超时、两台设备表现不同、3x-ui 面板打不开、TUN 或
IPv6 走错路、目标站拒绝代理出口、给单个节点绑定 SOCKS/HTTP 出口、搭建
VLESS Reality 或 Hysteria2、修改 TLS/DNS，以及检查多台 VPS 的配置漂移。
协议名和服务商标签都不能跳过证据检查。

## 安全限制该管什么

安全判断只围绕一件事：这次操作会不会切断当前 Codex 使用的路径。它不是
“SSH 写入一律禁止”。

| 场景 | `execution_mode` | 处理方式 |
| --- | --- | --- |
| 只读检查 | `read-only` | 在声明范围内直接执行 |
| 独立远端 VPS，不修改本机网络 | `direct-ssh-or-plan` | 说明影响并确认一次后，Codex 可以直接 SSH 完成备份、Linux 命令、校验、验证和失败回滚 |
| 与当前路径共享、并使用自动回滚的远端组件 | `exact-plan` | 使用不可变计划、新鲜控制通道证据、完整备份覆盖和已武装的回滚定时器 |
| 可能让 Codex 当场失联的本机 TUN、系统代理、代理进程、DNS、路由或防火墙切换 | `manual-local-control-plane` | 用户只完成这个本机切换，后续远端操作继续由 Codex 执行 |
| 安装或删除调度任务 | v0.3.1 尚未开放 | `monitor install/remove` 保持 fail-closed，只生成 dry-run 审查材料 |

允许直接 SSH，不等于允许随意修改。远端写入仍要有明确授权、受影响状态备份、
修改前校验、修改后新旧行为验证、可执行回滚和简短回执。独立目标也可以为文件
事务选择精确计划执行器，此时控制通道模式仍是 `direct-ssh-or-plan`。共享路径
只有在自动回滚合同通过门禁后才会进入 `exact-plan`。

同一个代理软件里的“备用节点”通常不算独立通道。只要重启软件或 TUN 会让两个
节点一起消失，它就保护不了当前连接。判断规则和失联恢复卡见
[Codex 控制通道安全](references/control-channel-safety.md)。

## 常用命令

### 检查一个 HTTPS 目标

```bash
netopsctl scan node \
  --target example.com \
  --port 443 \
  --tls \
  --http \
  --output node.json
```

### 只增加一个外部工具

外部适配器必须显式选择并授权。下面的命令只对声明过的目标增加五轮 MTR：

```bash
netopsctl tools list
netopsctl tools status --versions
```

`detected` 只表示找到了本地文件。版本和适配器实际使用的全部命令行能力都通过
检查后，状态才会变成 `usable`。

```bash
netopsctl scan node \
  --target example.com \
  --port 443 \
  --protocol tcp \
  --tls \
  --tool mtr \
  --external \
  --output node-mtr.json
```

节点扫描里的 `--external` 表示同意该工具发出说明过的网络请求。客户端和本机
服务器使用独立的 `--tool-external`；iperf3 还要再加 `--allow-load`。
NetOps 不会替你下载缺失工具，也不提供浮动版本的 `curl | bash` 安装方式。

### 比较两次观测

```bash
netopsctl scan compare \
  before.json \
  after.json \
  --output comparison.json
```

目标或诊断配置不一致时会拒绝比较。两边出现同一种失败，也不会被写成“正常”。

### 导出脱敏支持包

```bash
netopsctl bundle export node.json --output node-support.zip
netopsctl bundle inspect node-support.zip --report-output node-support-review.md
```

支持包默认移除网络标识和高置信凭据。归档校验和只能证明内部成员彼此一致，
不是数字签名，也不能证明文件是谁生成的。发给别人之前仍要人工检查。

### 执行审查过的精确变更

```bash
netopsctl change plan \
  --spec change-spec.json \
  --fleet fleet.json \
  --output change-plan.json

netopsctl change apply \
  --plan change-plan.json \
  --fleet fleet.json \
  --current-control-channel current-control-channel.json \
  --confirm-plan-id "$PLAN_ID" \
  --authorized \
  --receipt change-apply.receipt.json
```

`PLAN_ID` 必须是审查过的计划打印出的完整 ID。通过 Skill 操作时，新鲜的控制
通道证据文件由 Codex 生成；直接使用 CLI 时，操作者要提供与计划完全一致的证据。

下面任一条件不满足时，执行器会在第一次远程写入之前停止：没有授权、计划 ID
不一致、计划超过 24 小时、控制通道证据超过 15 分钟、目标前态变化，或者备份与
回滚没有覆盖全部目标。回执显示 `rollback-pending` 时，先等已经武装的回滚完成
并检查最终状态，不要立即重复应用。

### 只审查监控，不安装任务

```bash
netopsctl monitor install \
  --target example.com \
  --port 443 \
  --scope user \
  --dry-run

netopsctl monitor status --scope user
```

install 命令返回不可执行的审查材料。status 只检查受管本地文件、生命周期标记、
权限和哈希，不查询 systemd、launchd 或 Task Scheduler。兼容采样只能继续读取
早期版本留下的有效状态，匿名数据最多保留 7 天或 200 MB；目标、主机名、原始
命令输出、Header 和节点链接不会进入长期状态。

## 报告、数据与隐私

每次扫描都会写出带版本的 JSON 诊断包和中文 Markdown 报告。报告先写有直接
证据支持的最早失败区段，然后列出环境、可见路径、证据、一个推荐动作，以及本次
看不到的部分。命令退出码是 0，不代表整条路径一定健康。

数据边界如下：

- 公网 IP 查询只有在明确使用 `--external` 时才发生。
- 外部工具必须给出工具名和对应授权参数。
- 高流量测试还要单独确认负载。
- 客户端控制通道扫描只保存系统代理是否启用，不保存 PAC URL、代理地址或带
  凭据的环境变量值。
- 支持包默认移除 IP、域名、MAC、用户目录、节点链接、凭据 UUID、代理账号和
  常见 API Token。只有显式使用 `--include-network-identifiers` 才会保留网络
  标识。
- 真实主机资料放在符合 [`schemas/fleet.schema.json`](schemas/fleet.schema.json)
  的私有覆盖仓库；公开仓库只提供匿名示例。
- NetOps 不抓包，也不运行无限期后台探测。

脱敏规则宁可保守，但任何启发式都无法证明一串不透明字符一定安全。把 ZIP 发给
别人或上传到 issue 之前，必须再看一遍里面的内容。

## Skill 分工

平时只需要调用总入口 `netops`，它会把请求交给一个主要工作流：

| Skill | 负责的事情 |
| --- | --- |
| `netops-start` | 解释陌生术语，帮第一次接触 VPS 的用户选定观察点 |
| `netops-scan` | 从客户端、VPS、节点和已有监控状态收集只读证据 |
| `netops-build` | 审计、规划并执行获准的 3x-ui、Xray、节点、DNS、TLS 和出口变更 |
| `netops-fix` | 排查断连、超时、TUN、DNS、IPv6 和目标站拒绝 |
| `netops-manage` | 处理备份、升级、安全、容量、舰队漂移和监控 dry-run 审查 |

项目只保留这五个宽工作流。协议细节、服务商行为和故障案例放进
`references/`，不会因为多一个网站或运营商就再复制一套 Skill。

## 文档索引

| 文档 | 内容 |
| --- | --- |
| [可观测路径](references/observable-path.md) | 观察点、置信度，以及一次扫描不能证明什么 |
| [Codex 控制通道安全](references/control-channel-safety.md) | 直接 SSH、共享路径、回滚定时器和失联恢复 |
| [精选外部工具](references/curated-tools.md) | 版本、能力门禁、授权和数据披露 |
| [故障诊断模型](references/troubleshooting-model.md) | 怎样用证据缩小故障范围 |
| [小白报告规范](references/beginner-reporting.md) | 中文报告顺序和表达规则 |
| [术语表](references/glossary.md) | VPS、入站、出站、TUN、DNS、IPv4/IPv6 等概念 |
| [通用案例](references/cases/README.md) | 不含真实基础设施标识的参数化案例 |
| [搭建运行手册](references/build-runbook.md) | 3x-ui/Xray 变更前后的审查与验证 |
| [Fleet 示例](examples/fleet.example.json) | 公开、匿名的私有覆盖层结构 |
| [变更示例](examples/change-spec.example.json) | Schema 3.0 精确事务输入 |

## 兼容性和当前边界

| 项目 | 当前值 |
| --- | --- |
| 文档命令使用的稳定版本 | `v0.3.1` |
| Python | `3.10` 到 `3.14` |
| 核心运行时依赖 | 仅 Python 标准库 |
| 变更 spec/plan schema | `3.0`；`2.0` 计划必须重新生成 |
| Fleet 与诊断包 schema | `2.0` |
| 调度器写入 | 未发布；只有 dry-run 审查与受管文件状态 |

`v0.3.0` 的远端备份事务误开了 shell xtrace，已经被 `v0.3.1` 取代。请使用
`v0.3.1` 或更高版本。

CI 在 Linux 上覆盖 Python 3.10-3.14，在 macOS 和 Windows 上覆盖 3.10、
3.12、3.14。平台专属命令由夹具验证；CI 不连接真实 VPS，也不会写入调度器。

## 开发与验证

日常门禁只需要仓库和 Python。严格 Schema 检查额外使用一个固定版本的开发依赖：

```bash
python3 -m pip install "jsonschema==4.25.1"
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py .
python3 scripts/validate_skills.py .
python3 scripts/release_check.py . --require-jsonschema
```

发布制品还要通过双构建和全新安装门禁：

```bash
python3 -m pip install "build==1.3.0" "setuptools==83.0.0"
python3 scripts/reproducible_build.py . \
  --source-date-epoch 1720000000 \
  --output-dir release-dist
python3 scripts/package_smoke.py . --dist-dir release-dist
```

`1720000000` 是 CI 用来比较两次构建的固定时间。正式标签应改用标签提交的
committer timestamp，并保存最终制品哈希。这里证明的是同一固定工具链和环境中
可以重复构建，不承诺不同系统或 zlib 版本得到完全相同的归档字节。

提交改动时，请保留一个根路由和五个工作流、保持核心只用标准库，并在合同变化时
同步更新测试和 Schema。测试数据必须匿名。真实主机名、IP、凭据、节点链接、
UUID 和私有 fleet 数据都不应出现在 PR 或 issue 中。

提交可复现的故障时，请在
[GitHub issue](https://github.com/Con-Benksl/NetOps/issues) 中写明 NetOps
版本、操作系统、完整命令、预期结果和实际结果。需要附诊断包时，只上传已经人工
检查过的脱敏版本。

## 开源许可

NetOps 使用 [MIT License](LICENSE)。
