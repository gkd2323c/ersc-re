# ersc.dll 可疑行为静态审计

> 范围：只读静态分析；未运行游戏，未加载 `ersc.dll`。
> 样本：`ersc.dll`
> SHA256：`B34DA36F537DFCE14551E1083C5F19CE7E33D8235034EF03CD549DE4A9107594`

## 结论摘要

当前证据显示该 DLL 更像是一个高对抗性的 Elden Ring 联机 Mod 组件，而不是典型持久化恶意软件。但它具备多项高风险二进制特征：Themida 保护、RWX 壳区、TLS 回调/入口保护、隐藏导入、动态 API 解析、网络/TLS/LDAP 通信能力、Crashpad 崩溃处理、补丁检测/反作弊逻辑。

当前未发现强持久化证据，例如 `CurrentVersion\Run`、`RunOnce`、计划任务、服务安装、启动目录写入等明确字符串或导入。

## 样本与 PE 特征

| 项 | 结果 |
| --- | --- |
| 类型 | PE32+ AMD64 DLL |
| 文件大小 | 7,790,096 bytes |
| 编译时间 | 2026-04-22 06:46:31 |
| ImageBase | `0x180000000` |
| EntryPoint RVA | `0x30b380` |
| 导出 | `modengine_ext_init` |
| 签名 | 无 Authenticode 签名 |
| TLS | 存在 |
| NX | radare2 显示 `nx false` |
| Overlay | radare2 显示 `overlay true` |

## 高风险/可疑点

### 1. Themida 保护与 RWX 壳区

`.themida` 节段大小为 `0x546000`，权限为 `rwx`，熵值约 `6.52`。这表明大量代码/数据被壳保护，且运行时可写可执行。对普通软件而言这是强可疑特征；对商业保护壳或游戏 Mod 反分析场景则可能是作者的保护策略。

证据：

- `.themida` 节名存在。
- `.themida` 权限为 execute/read/write。
- YARA 规则 `Packed_Themida_RWX` 命中。

### 2. 可见导入极少，真实能力被隐藏

静态可见导入只有 8 项：

- `GetModuleHandleA`
- `GetAsyncKeyState`
- `SteamAPI_GetHSteamPipe`
- `WSACleanup`
- `BuildExplicitAccessWithNameW`
- `CertAddCertificateContextToStore`
- `WLDAP32.Ordinal_301`
- `IdnToAscii`

结合现有分析报告中的运行时 IAT 重建结果，实际运行时会解析更多 Windows API、Winsock、LDAP、Steam API。该差异说明导入表被混淆或运行时解密。

### 3. 网络、TLS、LDAP 能力明显

字符串和现有分析均显示它包含较完整的联网能力：

- Steam lobby / Steam networking
- libcurl
- HTTP/HTTPS
- SOCKS/proxy
- LDAP/LDAPS/STARTTLS
- TLS/SChannel
- SSL public key pinning

YARA 规则 `Network_TLS_LDAP_Curl` 命中。

风险判断：

- 对联机 Mod 来说，Steam 和自研匹配/目录服务可能合理。
- 但 LDAP/LDAPS 和证书固定意味着存在非 Steam 的远端服务交互，需要动态确认目标主机、端口、请求内容和是否上传用户/机器信息。

### 4. 加密与证书固定

命中字符串包括：

- `rsa(n)`
- `rsa(e)`
- `sha256`
- `sha512`
- `RSA Public Key`
- `SSL public key does not match pinned public key`

风险判断：

- 这可能用于保护联机协议、防中间人攻击。
- 也会增加流量审计难度，需要结合动态抓包和 API 参数记录判断是否存在数据外传。

### 5. AntiPatch / 反作弊检测逻辑

字符串中存在：

- `CSCheatDetectionSpider`
- `CSCheatDetectionSpider::WhatIsPatchBytes()`
- `PatchByte`

YARA 规则 `AntiPatch_CheatSpider` 命中。

风险判断：

- 这说明 DLL 会检查补丁/内存修改。
- 对 Mod 生态可能是检测作弊行为，也可能用于反分析/反篡改。
- 需要动态确认它检查哪些模块、哪些地址，以及是否把检测结果上报远端。

### 6. Crashpad 嵌入

字符串显示 Crashpad 相关文件写入和 handler 进程启动逻辑：

- `crashpad::ReadFile`
- `crashpad::internal::NativeWriteFile`
- `StartHandlerProcess`

YARA 规则 `Crashpad_Embedded` 命中。

风险判断：

- Crashpad 常用于崩溃上报，本身不等于恶意。
- 需要动态确认 crash dump 保存位置、上传目标和 dump 是否包含敏感信息。

## 未发现或弱证据

### 持久化

未发现明确强持久化证据：

- 未见 `CurrentVersion\Run`
- 未见 `RunOnce`
- 未见 `CreateService`
- 未见 `schtasks`
- 未见启动目录写入

少量 `service` / `Services` 命中更像 libcurl/URL 参数或通用字符串，不足以判断持久化。

### 真实公网 IOC

未提取到可信真实公网 URL/域名：

- URL 命中仅为 `https://curl.se/docs/alt-svc.html` 和 `https://curl.se/docs/http-cookies.html`，属于 libcurl 文档字符串。
- 域名命中仅有 `example.com`。
- IP 命中多数是 X.509 OID 形式的伪命中，只有 `127.0.0.1` 需要后续确认上下文。

## 动态验证优先级

下一步应优先用外部观察方式验证，不直接 hook 目标代码：

1. `ProcMon`：文件、注册表、进程、Crashpad dump 路径。
2. `TCPView` / `Get-NetTCPConnection`：连接目标、端口、进程关联。
3. `Wireshark`：Steam、LDAP、TLS 流量分流。
4. `x64dbg` 硬件断点：只记录参数和调用栈。

建议断点/API：

- `connect`
- `send`
- `recv`
- `sendto`
- `recvfrom`
- `ldap_initA`
- `ldap_sslinitA`
- `ldap_bind_sA`
- `ldap_search_sA`
- `CreateFile`
- `WriteFile`
- `VirtualProtect`
- `GetProcAddress`
- `LoadLibraryExA`

重点问题：

- 是否连接非 Steam/Yui 预期服务器？
- 是否上传 crash dump、配置、用户 ID、Steam ID、主机名？
- `CSCheatDetectionSpider` 的检测结果是否只本地使用，还是会上报？
- 是否存在游戏目录之外的文件写入？
- 是否存在注册表/服务/计划任务持久化行为？

## 本次使用的工具

- PowerShell `Get-FileHash`
- Python `lief`
- Python `yara`
- radare2 6.1.4 bundled binary
- 现有 `ersc_strings.txt`
- 现有 `ersc_analysis.md`

## 本次未运行的内容

以下脚本会加载 DLL 或可能执行目标代码，本次未运行：

- `iat_rebuilder.py`
- `iat_resolver.py`
- `dump_direct.py`
- `dump_ersc.py`
- Frida trace 脚本

## 动态验证补充（2026-06-03）

### 运行方式

通过 Steam + Mod Engine 2 正常启动：

- 启动脚本：`D:\SteamLibrary\steamapps\common\ELDEN RING\Game\launchmod_eldenring.bat`
- Mod 配置：`external_dlls = ["D:\\SteamLibrary\\steamapps\\common\\ELDEN RING\\Game\\SeamlessCoop\\ersc.dll"]`
- 游戏目录样本 SHA256 与工作区样本一致：`B34DA36F537DFCE14551E1083C5F19CE7E33D8235034EF03CD549DE4A9107594`

### 已确认加载模块

`eldenring.exe` 进程中确认加载：

- `SeamlessCoop\ersc.dll`
- `modengine2\bin\modengine2.dll`
- `steam_api64.dll`
- `WS2_32.dll`
- `WLDAP32.dll`
- `WINHTTP.dll`
- `WININET.dll`
- `CRYPT32.dll`
- `bcrypt.dll`
- `ncrypt.dll`
- `Normaliz.dll`

结论：静态分析中推断的网络、LDAP、TLS/证书、加密相关能力在运行时模块层面得到确认。

### 网络观察

监控窗口：

- 启动采样日志：`analysis\dynamic\dynamic-20260603-110533.jsonl`
- 联机操作采样日志：`analysis\dynamic\interactive-20260603-110838.jsonl`

联机操作期间，`eldenring.exe` 的 TCP 连接只观察到本机回环：

- `127.0.0.1:7897`
- `127.0.0.1:61256`
- `127.0.0.1:61257`

没有观察到 `eldenring.exe` 直接建立公网 TCP 连接。

同时，`eldenring.exe` 打开了大量 UDP 本地端口：

- `49298-49300`
- `54203`
- `62520-62544`

这更符合 Steam P2P / 游戏网络栈行为。由于 `Get-NetUDPEndpoint` 只暴露本地 UDP 端口，不显示远端地址，仍需要包捕获工具确认 UDP 对端。

尝试使用 `pktmon` 按 UDP 端口抓包失败：

- 错误：无法与 PktMon 驱动程序通信；系统找不到指定的文件。

### Crashpad 观察

当前存在两个 Crashpad handler：

1. Mod Engine Crashpad
   - 路径：`Game\modengine2\crashpad\crashpad_handler.exe`
   - 命令行包含 Sentry 上传 URL：
     `https://o484281.ingest.sentry.io/api/5537212/minidump/?sentry_key=...`
   - 这是 Mod Engine 自身崩溃上报。

2. SeamlessCoop Crashpad
   - 路径：`Game\SeamlessCoop\crashpad\crashpad_handler.exe`
   - 命令行包含本地数据库和 metrics 目录：
     `--database=SeamlessCoop\crashdumps`
     `--metrics-dir=SeamlessCoop\crashpad\crash_metrics`
   - 未观察到 `--url=...` 上传目标。

结论：本轮动态观察中，SeamlessCoop 自带 Crashpad 更像本地 dump 收集；Mod Engine 的 Crashpad 明确配置了 Sentry 上传。

### 文件写入观察

启动阶段出现以下写入：

- `Game\crashdumps\settings.dat`
- `Game\SeamlessCoop\crashdumps\settings.dat`
- `Game\SeamlessCoop\crashdumps\metadata`
- `Game\modengine2\logs\modengine_2026-06-03.log`
- `Game\modengine2\tools\scyllahide\scylla_hide.log`
- `Game\ReShade.log`

联机操作阶段未观察到新的文件写入。

### 动态结论

当前动态证据支持以下判断：

- `ersc.dll` 确实被 Mod Engine 加载进 `eldenring.exe`。
- 网络/LDAP/TLS/加密相关系统 DLL 在运行时被加载。
- 联机操作期间未观察到 `eldenring.exe` 直接公网 TCP 连接。
- 游戏进程打开大量 UDP 本地端口，疑似 Steam P2P/游戏网络；远端仍需抓包工具确认。
- 未观察到注册表/服务/计划任务持久化行为。
- 未观察到联机操作阶段新增文件写入。
- 未观察到 SeamlessCoop Crashpad 的上传 URL；Mod Engine Crashpad 有 Sentry 上传 URL。

待补证据：

- 使用 Wireshark/tshark/Npcap 或可用的 pktmon 驱动确认 UDP 对端。
- 用 x64dbg 硬件断点记录 `ldap_*`、`sendto`、`recvfrom`、`connect` 调用栈和参数。
- 如需确认 `CSCheatDetectionSpider` 是否上报结果，需要命中其运行时路径或抓到相关网络事件。

## 社区封禁能力讨论补充

后续社区讨论中出现一个更需要澄清的风险点：有玩家声称作者或管理方可以封禁特定玩家，使其无法使用 Seamless Co-op 进行联机，并会在 Discord 频道披露封禁结果。

该说法当前需要继续验证，不能仅凭社区讨论直接定性。但如果属实，它意味着 Mod 至少存在以下机制之一：

- 中心化封禁/授权服务
- 按 Steam ID 或其他玩家标识进行 denylist 检查
- 从远端同步封禁列表
- 将作弊/补丁检测结果上报给管理方
- 在会话建立时执行远端或半远端准入控制

本地字符串中存在一些相关但不充分的证据：

- `YKNX3_BREAKINBANNED`
- `FE_PKPLAYERBANISHED`
- `You have been blocked by the host of the session`
- `You have blocked the host of the session`
- `CSCheatDetectionSpider::WhatIsPatchBytes()`

其中，“被房主屏蔽/屏蔽房主”可以解释为本地主机/玩家级 block 功能，不等于作者级远程封禁。`YKNX3_BREAKINBANNED` 和 `FE_PKPLAYERBANISHED` 也可能是游戏入侵/联机状态事件，不能单独证明中心化封禁。

但结合以下事实：

- DLL 包含 `YuiKeyNexus3` 自研网络层；
- 运行时加载了 `WLDAP32.dll`；
- 静态分析中存在 AntiPatch / CheatDetectionSpider 逻辑；
- 社区声称存在管理方封禁特定玩家的行为；

这一点应被提升为“需要作者或 Nexus 明确澄清”的问题。

建议向作者/平台要求澄清：

1. 是否存在作者、管理员或服务端级别的玩家封禁能力？
2. 封禁依据是什么，是否来自 `CSCheatDetectionSpider` 或其他检测逻辑？
3. 被封禁玩家的标识是什么：Steam ID、账号 ID、IP、硬件信息，还是其他标识？
4. 封禁列表存储在哪里：本地、Steam、LDAP/目录服务、Discord bot，还是作者控制的后端？
5. DLL 是否会定期从远端拉取 denylist/banlist？
6. DLL 是否会上报玩家检测结果、Steam ID、会话信息或 crash/session metadata？
7. 玩家是否能查看、申诉或删除相关记录？
8. Discord 公示封禁结果是否包含 Steam ID、昵称或其他可识别信息？

更新风险判断：

- 即使当前抓包未发现非 Valve 主流量，作者级封禁能力如果属实，仍然代表中心化控制和玩家数据治理风险。
- 该风险不一定等同恶意软件，但属于隐私、透明度、申诉机制和平台治理问题。

### UDP 抓包补充（管理员 pktmon）

在管理员权限下通过 `analysis\dynamic\capture_eldenring_udp_admin.ps1` 成功启动 `pktmon`，按 `eldenring.exe` 当前 UDP 本地端口过滤，捕获 120 秒：

- ETL：`analysis\dynamic\pktmon-eldenring-20260603-112303.etl`
- PCAPNG：`analysis\dynamic\pktmon-eldenring-20260603-112303.pcapng`
- PCAPNG 大小：`37,871,544` bytes
- 过滤端口：`49298-49300`、`54203`、`62520-62544`

纯 Python 解析 PCAPNG 后，涉及 `eldenring.exe` UDP 本地端口的主要对端如下：

| 对端 | 入站包数 | 出站包数 | 说明 |
| --- | ---: | ---: | --- |
| `45.121.184.5:27025` | 51630 | 20196 | 主流量对端 |
| `103.28.54.179:27021` | 54 | 36 | 低频对端 |
| `162.254.195.70:27141` | 54 | 36 | 低频对端 |
| `205.196.6.149:27075` | 18 | 12 | 低频对端 |
| 多个 `270xx/271xx` 对端 | 每个 6 入站 / 4 出站左右 | 每个 4 出站左右 | Steam 风格探测/中继候选 |

其他低频对端包括：

- `146.66.152.36:27017`
- `155.133.225.18:27035`
- `155.133.224.21:27023`
- `103.10.125.20:27180`
- `162.254.194.38:27080`
- `155.133.226.87:27020`
- `103.10.124.118:27037`
- `155.133.248.40:27053`
- `162.254.199.180:27130`
- `162.254.192.124:27016`
- `155.133.252.37:27040`
- `162.254.193.73:27107`
- `185.25.183.179:27047`
- `185.25.182.18:27032`
- `155.133.227.56:27022`
- `155.133.238.178:27030`

判断：

- 捕获到的 UDP 流量集中在 `270xx/271xx` 端口，非常符合 Steam networking / Steam Datagram Relay 风格。
- 未在本次抓包摘要中观察到 LDAP 典型端口（389/636）或 HTTPS/TCP 外联由 `eldenring.exe` 直接发起。
- 仍需使用 IP 归属查询或 Wireshark/tshark 协议识别确认这些对端是否全部属于 Steam/Valve 相关网络。

### UDP 内容特征补充

进一步解析 `pktmon-eldenring-20260603-112303.pcapng` 后生成：

- `analysis\dynamic\pktmon-udp-analysis.json`

关键统计：

- 主对端 `45.121.184.5:27025`
  - 入站：`51630` 包，约 `9,346,572` UDP bytes
  - 出站：`20196` 包，约 `2,635,672` UDP bytes
  - 主要本地端口：`62530`
- 出站样本 payload 头部出现 ASCII 片段：`sdping`
  - 样本 hex：`0102736470696e67...`
  - ASCII：`..sdping...`

该 `sdping` 特征与 Steam Datagram / Steam networking 探测流量高度一致。结合 IPinfo/ASN 查询，`45.121.184.0/24` 属于 `AS32590 Valve Corporation`，因此主 UDP 对端当前判断为 Steam/Valve 中继或探测节点，而非可疑第三方服务。

更新判断：

- 本轮联机抓包没有发现 `ersc.dll`/`eldenring.exe` 直接访问非 Valve 的可疑 UDP 主对端。
- 当前网络行为更像 Steam P2P/SDR 中继流量。
- 若仍怀疑 `ersc.dll` 有自研服务通信，应继续盯 `WLDAP32!ldap_*` 或 `WINHTTP/WININET` 调用栈，而不是只看 UDP 对端。
