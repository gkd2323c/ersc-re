# 关于 Elden Ring Seamless Co-op `ersc.dll` 的安全分析结果

大家好，我最近对 Elden Ring Seamless Co-op v1.9.9 中的 `ersc.dll` 做了一轮安全向逆向分析。

分析目的不是指控作者或 Mod 存在恶意行为，而是确认这个 DLL 是否存在常见可疑行为，例如异常外联、持久化、数据上传、隐藏系统修改等。

## 样本信息

```text
文件名：ersc.dll
Mod：Elden Ring Seamless Co-op
版本：v1.9.9
SHA256：B34DA36F537DFCE14551E1083C5F19CE7E33D8235034EF03CD549DE4A9107594
```

## 结论摘要

目前没有发现明确恶意行为证据。

基于静态分析、动态运行、联机操作和 UDP 抓包结果，我倾向于认为：

> `ersc.dll` 更像是一个高对抗性、强保护的联机 Mod 组件，而不是典型恶意软件。

主要风险点是透明度和可审计性，而不是当前已经验证出的恶意行为。

## 已确认的高风险静态特征

该 DLL 具备一些高风险二进制特征：

- 使用 Themida 加壳
- 存在大型 RWX `.themida` 段
- 存在反调试 / 反分析特征
- 可见导入表很小，真实导入存在运行时解析或隐藏
- 会通过 Mod Engine 加载进 `eldenring.exe`
- 包含网络、TLS、加密、LDAP、Crashpad 等相关能力
- 存在 AntiPatch / 反作弊检测相关字符串和逻辑

这些特征并不等于恶意，但会显著增加普通用户和社区审核者独立审计的难度。

## 动态运行结果

通过 Steam + Mod Engine 2 正常启动游戏后，确认：

- `ersc.dll` 被加载进 `eldenring.exe`
- `modengine2.dll` 被加载
- `steam_api64.dll` 被加载
- `WS2_32.dll` 被加载
- `WLDAP32.dll` 被加载
- `WINHTTP.dll` / `WININET.dll` 被加载
- `CRYPT32.dll` / `bcrypt.dll` / `ncrypt.dll` 被加载

这说明静态分析中看到的网络、TLS、加密和 LDAP 相关能力在运行时确实存在。

但“模块被加载”不等于“实际发生了可疑联网行为”，所以我继续做了联机操作和抓包验证。

## 联机抓包结果

联机测试期间，`eldenring.exe` 没有观察到直接可疑公网 TCP 连接。

主要网络行为是 UDP 流量，集中在 Steam 风格的 `270xx/271xx` 端口段。

主 UDP 对端：

```text
45.121.184.5:27025
```

经 IP 归属查询，`45.121.184.0/24` 属于 Valve Corporation / AS32590。

进一步解析 UDP payload 后，样本中出现：

```text
sdping
```

该特征符合 Steam Datagram / Steam networking 探测或中继流量。

因此，目前抓到的主网络流量更像是 Steam P2P / Steam Datagram Relay，而不是 `ersc.dll` 自行连接第三方可疑服务。

## 没有观察到的行为

本轮分析中没有观察到以下行为：

- 注册表启动项
- `Run` / `RunOnce` 持久化
- 服务安装
- 计划任务创建
- 启动目录写入
- `eldenring.exe` 直接发起可疑公网 TCP 连接
- LDAP 典型端口 `389` / `636` 的实际联网流量
- 联机操作阶段新增异常文件写入
- SeamlessCoop 自带 Crashpad handler 配置上传 URL

## Crashpad 观察

运行时存在两个 Crashpad handler：

### Mod Engine Crashpad

Mod Engine 自带 Crashpad handler 配置了 Sentry 上传 URL。

这看起来属于 Mod Engine 自身的崩溃上报机制。

### SeamlessCoop Crashpad

SeamlessCoop 自带 Crashpad handler 使用本地数据库：

```text
SeamlessCoop\crashdumps
```

本轮观察中没有看到它配置 `--url=` 上传目标。

因此当前证据更像是本地 crash dump 收集，而不是远端上传。

## 风险判断

当前我会把风险分成两类：

### 已验证但不等于恶意的高风险特征

- Themida 加壳
- RWX 壳区
- 反调试 / 反分析
- 运行时导入解析
- 游戏进程 hook
- AntiPatch / 反作弊检测
- Crashpad 本地 dump

这些特征会让二进制很难被审计，但在商业保护、游戏 Mod、防作弊和兼容性场景下也可能有合理解释。

### 当前未验证出的问题

- 未发现恶意持久化
- 未发现非 Valve 主网络对端
- 未发现 LDAP 实际外联
- 未发现 SeamlessCoop Crashpad 上传 URL
- 未发现联机操作时异常文件写入

## 需要额外澄清的问题：作者级封禁能力

后续社区讨论中出现了一个比混淆本身更值得关注的问题：有玩家声称作者或管理方可以封禁特定玩家，使其无法使用 Seamless Co-op 进行联机，并会在 Discord 频道披露封禁结果。

我目前不能仅凭社区讨论确认这个说法属实，但如果属实，它意味着 Mod 可能存在某种中心化封禁、授权或 denylist 机制。

这与当前分析中的几个点存在关联：

- DLL 包含 `YuiKeyNexus3` 自研网络层
- 运行时加载了 `WLDAP32.dll`
- 字符串中存在 `CSCheatDetectionSpider`
- 字符串中存在 `YKNX3_BREAKINBANNED`
- 字符串中存在 `FE_PKPLAYERBANISHED`
- 字符串中存在 “You have been blocked by the host of the session”
- 字符串中存在 “You have blocked the host of the session”

需要强调的是，这些字符串本身不能证明作者可以远程封禁玩家。

“被房主屏蔽”也可能只是本地房主/玩家级 block 功能；`YKNX3_BREAKINBANNED` 和 `FE_PKPLAYERBANISHED` 也可能是游戏入侵或联机状态事件。

但结合社区讨论，这一点应该由作者或平台正式澄清。

我认为需要明确回答以下问题：

- 是否存在作者、管理员或服务端级别的玩家封禁能力？
- 封禁依据是什么？
- 是否使用 Steam ID、账号 ID、IP、硬件信息或其他标识？
- 封禁列表存储在哪里？
- DLL 是否会从远端拉取 denylist / banlist？
- `CSCheatDetectionSpider` 的检测结果是否会上报？
- 玩家是否能查看、申诉或删除相关记录？
- Discord 公示封禁结果是否包含可识别玩家身份的信息？

如果作者确实有能力阻止特定玩家使用该 Mod 联机，那么这不一定等同恶意软件，但属于非常重要的透明度、隐私和治理问题。

## 我的阶段性结论

基于目前证据，我不认为可以把该 DLL 定性为恶意软件。

更准确的说法是：

> `ersc.dll` 是一个高度混淆、强保护、深度 hook 游戏进程的联机 Mod DLL。  
> 它具备较强的反分析和网络能力，但在本轮测试中没有观察到明确恶意行为。

如果社区继续关注这个问题，我建议重点放在“透明度”和“可审计性”上，而不是直接进行恶意指控。

## 已公开的分析材料

分析材料已整理到 GitHub：

```text
https://github.com/gkd2323c/ersc-re
```

核心文件：

```text
analysis/suspicious_behavior_static_audit.md
analysis/dynamic/pktmon-udp-analysis.json
```

说明：

- 原始抓包文件没有上传
- dump 文件没有上传
- 本地路径和敏感运行日志没有作为主要证据公开
- GitHub 中主要保留报告和派生统计结果

## 后续可继续验证的方向

如果有人想进一步复核，可以继续做：

- 用 x64dbg 硬件断点记录 `WLDAP32!ldap_*` 是否实际被调用
- 记录 `WS2_32!sendto` / `recvfrom` 的调用栈
- 确认 UDP 调用栈是否来自 Steam networking
- 检查 Crashpad dump 内容是否包含敏感数据
- 对 `.themida` 壳区做更深入的定点分析

## 免责声明

这份分析只是一次社区安全透明度审计。

当前证据不支持“该 Mod 是恶意软件”的结论。

如果后续有人发现新的证据，欢迎基于样本哈希、抓包、调用栈或可复现实验继续补充。
