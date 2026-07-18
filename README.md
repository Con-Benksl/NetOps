# NetOps

VPS 网络出问题时，真正麻烦的往往不是少了一条命令，而是不知道问题出在哪一段：是电脑、家里的网络、VPS、代理配置、上游出口，还是目标网站本身？

NetOps 就是用来查这件事的。它包含一组可供 Codex 使用的 Agent Skills，以及一个只依赖 Python 标准库的诊断工具。你可以直接用中文描述问题，也可以在命令行里运行扫描。

它的做事顺序很简单：**先扫描，再判断；先给方案，再改服务器。** 没有明确授权、备份和回滚方案时，NetOps 不会直接修改远程配置。

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
| 两台设备对比 | 在目标、协议和时间窗口一致时比较两份诊断结果 |

运营商和代理服务商的内部网络通常无法完全看见。报告会把这类区段标成“无法观测”，不会拿一次 traceroute 或 ASN 查询冒充完整线路图。

## 最简单的用法

### 方式一：作为 Codex Skill 使用

全局安装：

```bash
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills add Con-Benksl/NetOps -g -y
```

安装后，直接描述你遇到的情况即可。例如：

```text
先只读扫描这台电脑和我的 VPS，看看节点为什么偶尔断连。

比较这两台电脑的诊断包，确认问题发生在哪一段。

帮我规划一个新的 VLESS Reality 入站，旧节点和 VPS 默认出口都不能改变。

给这个节点安装故障监控，但先只显示计划，不要执行。
```

如果信息不够，NetOps 会优先建议只读扫描。需要改服务器时，它会先说明准备改什么、如何验证以及怎样回滚，再等待授权。

### 方式二：直接运行命令行工具

需要 Python 3.10 或更高版本：

```bash
git clone https://github.com/Con-Benksl/NetOps.git
cd NetOps
python3 scripts/netopsctl.py --help
```

扫描当前电脑：

```bash
python3 scripts/netopsctl.py scan client --output client.json
```

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

比较两份条件一致的节点诊断包：

```bash
python3 scripts/netopsctl.py scan compare left.json right.json --output comparison.json
```

先查看监控安装计划，不写入系统任务：

```bash
python3 scripts/netopsctl.py monitor install \
  --target example.com \
  --port 443 \
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

## 五个工作流程

日常使用只需要记住总入口 `netops`。它会根据问题选择下面一个主要流程：

| Skill | 负责什么 |
| --- | --- |
| `netops-start` | 解释术语，帮助第一次接触 VPS 的用户确定从哪里开始 |
| `netops-scan` | 扫描客户端、VPS、节点和当前可见的传输路径 |
| `netops-build` | 搭建或修改 3x-ui、Xray、节点、DNS、TLS 和专属出口 |
| `netops-fix` | 诊断断连、超时、TUN、DNS、IPv6 和目标站拒绝等问题 |
| `netops-manage` | 处理监控、备份、升级、安全、容量和多 VPS 标准化 |

协议说明和具体故障案例放在 `references/` 中，不会因为多了一个网站或运营商就再增加一套 Skill。

## 监控会保存什么

默认监控每 60 秒做一次轻量检测，每 15 分钟保存一份完整状态。连续失败 3 次后，会临时改为每 5 秒记录一次，持续 10 分钟，并分别保存故障发生和恢复时的快照。

数据只保存在本机，默认保留 7 天或最多 200 MB，以先达到的限制为准。NetOps 不会默认保存数据包内容；临时抓包需要单独授权，并且必须限制时间。

桌面系统使用现成的计划任务：Linux 用 systemd timer，macOS 用 launchd，Windows 用 Task Scheduler。项目不会额外安装一个长期以高权限运行的自研守护进程。

## 数据和隐私

- 公网 IP 查询只有在明确使用 `--external` 时才会发生。
- 导出的诊断包默认会隐藏 IP、域名、用户目录和疑似凭据。
- 密码、私钥、节点链接、UUID、代理账号和 API Token 不应写入仓库或报告。
- 公开仓库只提供匿名示例。真实主机资料应放在符合 `schemas/fleet.schema.json` 的私有覆盖仓库中。
- 扫描只适用于你拥有或明确获准管理的设备。

## NetOps 不会做什么

- 不做无边界端口扫描、密码猜测或未经授权的远程操作。
- 不把“端口能连通”直接解释成 VLESS、Hysteria2 等协议一定正常。
- 不承诺还原运营商和服务商内部无法观测的完整物理线路。
- 不会为了修一个节点，默认改变整台 VPS 的出口或覆盖已有配置。
- 不会在没有计划 ID、明确授权、备份和回滚信息时执行远程变更。

## 开发与测试

项目核心只使用 Python 标准库。提交前运行：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py .
python3 scripts/validate_skills.py
```

CI 会在 Linux、macOS 和 Windows 上测试 Python 3.10 与 3.12。平台专属命令使用夹具和命令生成测试验证，不会在 CI 中连接真实 VPS。

## 开源许可

NetOps 使用 [MIT License](LICENSE) 开源。

你可以自由使用、修改和分发本项目，也可以用于商业用途，但需要保留原有的版权和许可声明。项目按现状提供，作者不对使用过程中产生的问题承担担保责任。完整条款请查看仓库中的 `LICENSE` 文件。
