# NetOps

NetOps 是一套面向 VPS 网络与代理运维新手的 Agent Skills 和只读诊断工具。它先发现环境，再解释证据，不会因为用户提到某个城市、运营商、网站或客户端，就把单次经验当作通用结论。

## 能做什么

- 用自然语言把请求分流到新手引导、扫描、搭建、排障或长期管理。
- 扫描 Windows、macOS、Linux 客户端以及本地或 SSH 可达的 Linux VPS。
- 检查 DNS、路由、TUN 痕迹、IPv4/IPv6、端口、TLS、HTTP、监听、服务和系统资源。
- 生成带置信度和盲区说明的可观测链路报告。
- 比较两台设备在相同目标、协议和时间窗口下的诊断包。
- 使用系统计划任务保存本地监控基线和限时故障记录。
- 为远程配置变更生成带哈希 ID 的计划，并要求明确授权后才执行。

NetOps 不提供无边界端口扫描、密码猜测、持续抓包或未经授权的远程操作。

## Skills

| Skill | 用途 |
| --- | --- |
| `netops` | 唯一自然语言总入口 |
| `netops-start` | 新手引导和术语解释 |
| `netops-scan` | 环境、服务器和节点链路扫描 |
| `netops-build` | 3x-ui/Xray、节点、DNS、TLS 和节点出口变更 |
| `netops-fix` | 断连、超时、TUN、DNS、IPv6 和目标站问题诊断 |
| `netops-manage` | 监控、备份、升级、安全和多 VPS 管理 |

协议、运营商、目标网站和单一故障类型都只存在于参考资料或案例中，不会继续增加子 Skill。

## 安装

安装 Skills：

```bash
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills add Con-Benksl/NetOps -g -y
```

直接运行诊断工具：

```bash
python3 scripts/netopsctl.py --help
python3 scripts/netopsctl.py scan client --output client.json
python3 scripts/netopsctl.py scan node --target example.com --port 443 --tls --output node.json
python3 scripts/netopsctl.py bundle inspect client.json
```

可选安装 Python 命令：

```bash
python3 -m pip install .
netopsctl --help
```

## 数据和隐私

- 默认只在本机写入诊断数据。
- 公网 IP 查询必须显式传入 `--external`。
- 导出的诊断包默认把 IP、域名、用户目录和疑似凭据替换为稳定匿名标签。
- 监控默认保留 7 天或 200 MB，以先达到者为准。
- 公开仓库只包含匿名示例。真实主机资料使用符合 `schemas/fleet.schema.json` 的私有覆盖仓库。

## 可观测链路

NetOps 报告的是不同观察点取得的证据：

```text
客户端 -> 接入网络 -> VPS 入站 -> 代理路由 -> 上游出口 -> 目标站
```

部分 ISP、代理服务商内部路径和回程通常不可见。NetOps 会把它们标记为盲区，不把 traceroute 或 ASN 查询包装成完整物理线路。

## 开发

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py .
python3 scripts/validate_skills.py .
```

项目仅使用 Python 标准库。自动化测试覆盖 Linux、macOS 和 Windows；平台专属命令通过夹具和命令生成测试验证。

## License

MIT
