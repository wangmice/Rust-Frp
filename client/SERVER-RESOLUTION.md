# 客户端服务端地址解析

控制连接的 TCP / TLS / WS / WSS、KCP、QUIC 和 NLink QUIC 共用以下解析顺序，无须新增配置开关：

1. 查询 `server_addr`（官方格式 `serverAddr`）的 TXT。每条记录单独拼接其字符串片段，Base64 解码为 `IPv4:port`。
2. TXT 查询失败或没有合法目标时，查询 AAAA 并识别 IP4P（严格 `2001::/80`）：`2001:0:0:0:0:端口:IPv4高16位:IPv4低16位`。
3. 没有合法 IP4P 时，回退普通 A / AAAA，使用配置的 `server_port` / `serverPort`。IP4P 编码地址不会作为普通 IPv6 使用。

TXT / IP4P 内的端口覆盖配置端口，必须为 1–65535。已获得合法目标但连接失败时，不自动切换其他记录类型；重连会重新执行解析。

## DNS 配置

`dnsServer` 为空时使用操作系统 DNS 配置；设置时使用指定 DNS，可写 `192.0.2.53`、`192.0.2.53:5353` 或 `[2001:db8::53]:5353`。系统和自定义 DNS 共用 TXT / IP4P 解码逻辑，不写死公共 DNS。

TXT 和 IP4P AAAA 探测各最多等待 1 秒；普通地址回退总预算为 3 秒。系统模式普通地址使用原生 resolver（保留 hosts / NSS 等机制），并遵循系统返回顺序；自定义 DNS 普通地址优先 A，再普通 AAAA。系统 DNS 配置无法读取时跳过特殊记录探测，仍尝试原生地址解析。特殊记录探测基于读取到的系统 DNS 配置，未覆盖 macOS 按域 VPN 等平台专有 DNS 路由机制；有此需求可显式设置 `dnsServer`。

示例（原生配置）：

```toml
server_addr = "frp.example.com"
server_port = 7000
# dnsServer = "192.0.2.53:53"
```

TXT 内容为目标 `IPv4:port` 的 Base64 编码，不是 URL，不支持域名目标或 IPv6 目标。支持标准 / URL-safe Base64、带或不带完整 padding、ASCII 空白及一层配对外部单双引号；拒绝错误 padding、混用字符表、非法编码或非 IPv4:port 内容。不同 TXT 记录不会相互拼接。

每次最多检查 16 条 TXT，每条拼接后最多 1024 字节。空白兼容只适用于编码文本；解码后的地址不允许空白或控制字符。

DNS 服务商界面 / `dig` 输出中的引号通常只是展示格式，DNS 报文里的 TXT 字符串片段不含这些展示用引号；无需手工添加。不会进行 URL 解码、shell 转义或任意删除非法字符。

## 连接与安全

- 出站 HTTP CONNECT / SOCKS5 代理使用解析后的 IP 和端口。
- TLS SNI / 证书身份、WebSocket Host 继续使用原始配置域名（或已有的显式覆盖配置）。
- 显式 `nlink.quic_addr` 也使用同一解析流程。
- P2P 牵线及 VirtualNet 使用独立业务端口，本次不套用控制连接记录里的端口。
- TXT / IP4P 不是认证机制，也不是加密方式。DNS 被篡改可能改变连接目标；应启用 TLS 并正确配置服务端证书校验。
- 普通域名现在会先查询 TXT 和 AAAA，DNS 超时时可能增加连接前的等待时间。
