# 🧬 Evolving Sniffer - 自进化协议分析工具

类似 Wireshark 的跨平台网络协议分析器，由 AI 自主进化开发。

## 目标

构建一个跨平台分布式协议分析工具：
- **主程序 (Controller)**: Windows，提供 GUI/CLI，管理代理，聚合展示数据包
- **Linux 代理 (Agent)**: 捕获原始网络数据包，发送给主程序

### 支持协议（渐进式）
- Phase 1: Ethernet/IP/TCP/UDP 解析 ✨ *当前目标*
- Phase 2: HTTP 请求/响应解析
- Phase 3: DNS 查询/响应解析
- Phase 4: HTTPS/TLS 元数据（SNI等）
- Phase 5: FTP 命令/响应解析
- Phase 6: SFTP (SSH) 包结构识别

## 进化机制

- 每 6 小时自动迭代一次
- 每次迭代：读取代码 → 规划改进 → 生成代码 → 运行测试 → 提交/回滚
- 使用 DeepSeek API 作为 LLM 引擎
- 自动推送到 GitHub

## 目录结构

```
evolving-sniffer/
├── agent/
│   ├── core.py      # 进化循环核心
│   ├── models.py    # LLM 接口
│   ├── coder.py     # 代码读写和测试
│   └── memory.py    # 经验记忆
├── target/          # 目标代码（协议分析器）
├── memory/          # 进化日志
├── config.py        # 配置
├── .env             # API 密钥
└── evolve_and_push.sh
```
