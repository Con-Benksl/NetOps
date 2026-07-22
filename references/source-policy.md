# 证据和来源策略

## 优先级

1. 当前设备和服务器的只读观测。
2. 已安装软件输出、配置测试和官方文档。
3. 协议标准、操作系统官方文档和供应商状态页。
4. 多个独立外部测量点。
5. 单个 IP 标签网站、论坛经验和历史记忆。

低优先级来源不能覆盖现场证据。

## 版本记录

任何易变化规则都要写：

- 软件或协议版本；
- 验证日期；
- 官方来源链接；
- 适用条件；
- 已知例外。

现场版本必须重新读取，不能把案例版本当作当前版本。

## 基础来源

- Xray routing: https://xtls.github.io/en/config/routing.html
- Xray outbound and target strategy: https://xtls.github.io/en/config/outbound.html
- Hysteria 2 troubleshooting: https://v2.hysteria.network/docs/advanced/Troubleshooting/
- v2rayN Wiki: https://github.com/2dust/v2rayN/wiki
- Cloudflare IPv6 behavior: https://developers.cloudflare.com/network/ipv6-compatibility/

外部服务只在任务需要时调用，并向用户说明会发送哪些最小数据。

## 外部工具

- 精选清单、权限和兼容基线见 `curated-tools.md`。
- 已安装工具的结构化输出仍要记录版本、观察点、目标、时间、限制和原始返回状态。
- 不把工具热度、星标数量或聚合评分当作正确性证明。
- 不通过 `curl | bash` 运行浮动版本；使用系统包或经过审核的官方稳定版本，并在升级后重新验证参数和输出结构。
- GPL/AGPL 工具作为独立程序调用。NetOps 不复制其源码，也不删除其来源和许可证信息。
