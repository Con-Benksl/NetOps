# 精选外部工具与兼容规则

最后核验：2026-07-20

NetOps 核心仍然只使用 Python 标准库。下面六个项目作为独立外部工具接入：NetOps 负责选择、授权、限制参数、解析结果和写入诊断包，不复制它们的源码，也不会静默下载或自动更新。

## 为什么只选这六个

| 工具 | 最适合回答的问题 | 接入方式 | 上游当前稳定版 / NetOps 最低兼容版 |
| --- | --- | --- | --- |
| [MTR](https://github.com/traviscross/mtr/tree/v0.96) | 哪一段开始出现持续延迟、抖动或端到端丢包？ | 5 轮报告模式，JSON | 上游 v0.96；最低 v0.95，且本机必须实际支持适配器使用的全部 JSON、报告和协议参数 |
| [NextTrace](https://github.com/nxtrace/NTrace-core/releases/tag/v1.7.1) | 当前去程经过哪些可见跳点？TCP/UDP 路径是否不同？ | 3 次采样、最多 30 跳，JSON | v1.7.1；Windows 为实验性支持，TCP/UDP 需要管理员权限和 WinDivert |
| [dnsdiag](https://github.com/farrokhi/dnsdiag/releases/tag/v2.9.4) | 指定 DNS 解析器是否延迟高、抖动大或丢包？ | `dnsping` 5 次查询 | dnsdiag 2.9.4；必须支持显式解析器端口 |
| [testssl.sh](https://github.com/testssl/testssl.sh/releases/tag/v3.2.4) | TLS 协议、证书或服务端默认参数是否异常？ | 聚焦 TLS 检查，JSON 文件 | testssl.sh 3.2.4；IPv6 目标必须使用方括号形式 |
| [IPQuality](https://github.com/xykt/IPQuality/tree/44c35cca002782ddd6364e039be2949a2535d1cc) | 当前出口在多个数据库中被怎样分类？ | 隐私模式、禁止装依赖、JSON 文件 | 固定提交 `44c35cca002782ddd6364e039be2949a2535d1cc`；Bash 4+ |
| [iperf3](https://github.com/esnet/iperf/releases/tag/3.21) | 两个自有端点之间是否存在明显吞吐差异？ | 有界时长、TCP 约 10 Mbit/s 或 UDP 约 5 Mbit/s，JSON | 上游 3.21；最低 3.16，且本机必须实际支持限时、限速、连接超时和 JSON 参数 |

这些工具并不互相替代。MTR 适合连续采样，NextTrace 适合路径快照；IPQuality 提供的是外部数据库线索，不是线路健康证明；iperf3 测的是两个受控端点之间的主动流量，不是公网测速网站给出的综合评分。

## 小白选择顺序

Codex 不应一次把六个工具全部运行。先根据现象给 2–3 个选项：

1. `基础扫描（推荐）`：只用 NetOps 内置的 DNS、TCP、TLS 和 HTTP 检查，不依赖外部工具。
2. `增强诊断`：根据现象只选一个工具，例如偶发超时用 MTR、线路快照用 NextTrace、解析问题用 dnsdiag。
3. `专项检测`：IP 信誉用 IPQuality；TLS 深度检查用 testssl.sh；自有端点性能对比用 iperf3。

每次只推荐一个主要下一步。工具缺失时，优先让用户选择继续基础扫描，还是审核官方来源和版本后安装；不能因为工具缺失就自动执行安装脚本。

## 权限与数据边界

- 任何精选工具都必须显式授权。节点扫描使用 `--external`；客户端或本机服务器扫描使用 `--tool-external`，从而与单独的公网出口身份查询 `--external` 保持隔离。这表示用户知道该工具会向声明的目标、解析器或第三方服务发出网络请求。
- iperf3 还必须单独使用 `--allow-load`。这表示用户确认目标是自己拥有或获准测试的 iperf3 服务。
- IPQuality 的 `-p` 只关闭在线报告生成，多个信誉和服务提供商仍能看到查询出口；报告必须保留这一限制。
- NextTrace 默认添加 `--data-provider disable-geoip`，不把每一跳地址额外发送给 GeoIP 服务。线路名称需要时应单独征得外部元数据查询同意。
- testssl.sh 只检查用户明确声明的 TLS 主机和端口，不接受目标文件或批量扫描。
- testssl.sh 可能执行目标 DNS 和反向 DNS 查询；这属于目标检查的一部分，报告必须披露，不能声称完全不产生旁路查询。
- dnsdiag 必须提供 `--resolver`；NetOps 不会擅自把系统 DNS 换成某个公共 DNS。
- 目标和解析器始终作为参数数组传递，不经过 shell 拼接；以 `-` 开头的值会被拒绝。

## 安装与发现

先查看目录和本机状态。不要假设当前目录是仓库；使用已安装的 `netopsctl`，或先解析 Skill 根目录再运行脚本：

```bash
netopsctl tools list
netopsctl tools status --versions
```

`tools status` 会区分 `detected`、`platform_supported`、`compatibility_checked` 与 `usable`。仅在 PATH 中发现同名文件不代表可用；没有完成版本和能力核验时，`compatible` 为 `null`，`usable`/兼容字段 `available` 都保持 `false`。发布诊断前应使用 `--versions` 完成本地、非网络的兼容性检查。

MTR 和 iperf3 优先使用操作系统软件包，但“上游当前稳定版”不是硬性的最低兼容版。例如 [Ubuntu 24.04 的 mtr-tiny](https://packages.ubuntu.com/noble/mtr-tiny) 是 0.95、[iperf3](https://packages.ubuntu.com/noble/iperf3) 是 3.16；[Debian 13 的 mtr-tiny](https://packages.debian.org/trixie/mtr-tiny) 是 0.95、[iperf3](https://packages.debian.org/trixie/iperf3) 是 3.18。NetOps 接受达到上述最低版本且能力探测完整通过的系统包；仅版本号合格仍不算可用。NextTrace、dnsdiag 和 testssl.sh 使用官方稳定发行版。IPQuality 没有稳定的本机命令名，因此必须先审核官方 `ip.sh`，再显式提供路径。

| 工具 | 显式路径变量 |
| --- | --- |
| MTR | `NETOPS_TOOL_MTR` |
| NextTrace | `NETOPS_TOOL_NEXTTRACE` |
| dnsdiag 的 `dnsping` | `NETOPS_TOOL_DNSDIAG` |
| testssl.sh | `NETOPS_TOOL_TESTSSL` |
| IPQuality 的 `ip.sh` | `NETOPS_TOOL_IPQUALITY` |
| iperf3 | `NETOPS_TOOL_IPERF3` |

环境变量只能包含一个本地文件路径，不能放命令、参数、URL 或管道。二进制必须可执行；testssl.sh 和 IPQuality 脚本必须可读，并由适配器直接交给 Bash。启动精选工具时只传递 PATH、临时目录、区域设置、系统根目录和证书目录等运行必需变量；不会继承无关 API Token、SSH 变量或 HTTP/SOCKS 代理变量，避免第三方程序看到与本次诊断无关的秘密或悄悄改变声明的观察路径。

NetOps 不提供 `curl | bash` 安装流程。升级外部工具时应记录官方来源、稳定版本或提交、校验和与核验日期，然后运行 `tools status --versions` 和单元测试。版本号只是第一道门：还要探测实际参数和结构化输出能力。上游命令行或 JSON 结构改变时，适配器必须返回 `unsupported` 或 `unknown`，不能静默回退到纯文本猜测，也不能把命令退出码 0 当作网络健康。

## 使用示例

对声明的 HTTPS 节点做 MTR：

```bash
netopsctl scan node \
  --target example.com --port 443 --protocol tcp --tls \
  --tool mtr --external --output node-mtr.json
```

检查指定解析器：

```bash
netopsctl scan node \
  --target example.com --port 53 --protocol udp \
  --tool dnsdiag --resolver 192.0.2.53 --external \
  --output dnsdiag.json
```

在 VPS 本机检查当前出口的 IP 质量：

```bash
NETOPS_TOOL_IPQUALITY=/opt/netops-tools/ipquality/ip.sh \
netopsctl scan server --local \
  --tool ipquality --tool-external --output ip-quality.json
```

只有在目标是获准使用的 iperf3 服务时运行受控性能样本：

```bash
netopsctl scan node \
  --target perf.example.com --port 5201 --protocol tcp \
  --tool iperf3 --external --allow-load --output throughput.json
```

## 没有直接接入的脚本

- goecs、YABS、LemonBench：组合了测速、磁盘、CPU、第三方查询或结果上传，副作用过多，只保留人工参考。
- NodeQuality：缺少足够透明、稳定的官方源码与许可证链路。
- 各类流媒体解锁脚本：结果随服务策略快速变化，只能作为特定目标的临时对照。
- bench.sh 和大量派生一键脚本：输出契约、更新方式或依赖来源不足以支撑稳定自动化。
- masscan、zmap、hping3 等主动扫描工具：不符合 NetOps 面向授权设备、限定目标的边界。

这些项目可以出现在解释材料中，但不能作为默认依赖、自动安装项或诊断结论来源。
