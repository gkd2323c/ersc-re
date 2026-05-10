# ersc.dll 逆向分析报告

> 目标：Elden Ring Seamless Co-op v1.9.9（作者 Yui）
> 保护：Themida 3.x 商业加壳
> 分析日期：2026-05-08 ~ 2026-05-10
> 工具：radare2 6.1.4 + Python pefile + x64dbg + ScyllaHide

---

# 一、概览与身份

## 1.1 文件身份

| 属性     | 值                                                     |
| ------ | ----------------------------------------------------- |
| 文件名    | ersc.dll                                              |
| 文件大小   | 7,790,096 字节 (7.8 MB)                                 |
| 类型     | PE32+ (AMD64), 16 个节段                                 |
| 编译时间   | 2026-04-22 06:46:31 UTC                               |
| 镜像基址   | 0x180000000                                           |
| 入口点    | 0x18030b380                                           |
| PDB 路径 | `C:\Users\Yui\source\repos\ersc\x64\Release\ersc.pdb` |
| 编译器    | MSVC (Microsoft Visual Studio)                        |

## 1.2 身份确认

- 字符串 `"Elden Ring Seamless Co-op mod by Yui [ YuiKeyNexus Version 3 ]"`
- 字符串 `"Elden Ring Seamless Co-op v1.9.9 by Yui"`
- 目标进程 `eldenring.exe`
- 唯一导出函数 `modengine_ext_init`（Mod Engine 2 注入接口）

## 1.3 节段布局

| 节段             | 虚拟大小          | 物理大小          | 权限      | 熵值       | 说明                  |
| -------------- | ------------- | ------------- | ------- | -------- | ------------------- |
| `.text`        | 1,589,248     | 1,624,064     | r-x     | 6.48     | 主体代码（可读，未加密）        |
| `.rdata`       | 548,864       | 545,792       | r--     | 6.09     | 只读数据（字符串/常量）        |
| `.data`        | 36,864        | 8,192         | rw-     | 2.82     | 可写数据                |
| `.pdata`       | 61,440        | 58,368        | r--     | 6.18     | 异常处理表               |
| `.00cfg`       | 4,096         | 512           | r--     | 0.50     | CFG 控制流保护           |
| `.gxfg`        | 16,384        | 12,800        | r--     | 5.25     | XFG 扩展流保护           |
| `.retplne`     | 4,096         | 512           | ---     | 1.05     | 返回地址区域              |
| `.tls`         | 4,096         | 512           | rw-     | 0.02     | 线程局部存储              |
| `_RDATA`       | 4,096         | 512           | r--     | 4.20     | 额外只读数据              |
| `.rsrc`        | 4,096         | 512           | r--     | 2.35     | 资源                  |
| `.reloc`       | 8,192         | 5,632         | r--     | 5.28     | 重定位表                |
| `.edata`       | 4,096         | 512           | r--     | 0.81     | 导出表                 |
| `.idata`       | 4,096         | 1,024         | rw-     | 2.35     | 导入表                 |
| `.tls_1`       | 4,096         | 512           | rw-     | 0.28     | 线程局部存储              |
| **`.themida`** | **5,529,600** | **5,529,600** | **rwx** | **6.52** | **Themida 保护壳（加密）** |
| `.reloc_1`     | 4,096         | 16            | r--     | 2.47     | 重定位表                |

> `.themida` 段占文件总大小的 71%，熵值 6.52 表明高度压缩/加密。

## 1.4 源码树还原

从嵌入的编译路径字符串还原：

```
ersc/
├── ersc.cpp                              # 主入口：modengine_ext_init
├── hooks.cpp                             # 游戏函数钩子
├── signatures.cpp                        # AOB 内存签名扫描
├── networking.cpp                        # 网络通信层
├── param.cpp                             # 游戏参数/配置管理
├── spectate.cpp                          # 观战系统
├── buddy.cpp                             # 伙伴系统
├── battle_royale.cpp                     # 大逃杀游戏模式
├── game_memory_unlimiter.cpp             # 游戏内存扩容
├── yui_nexus_3/
│   └── yui_neuxs_3.cpp                  # YuiKeyNexus V3 网络框架
├── seamless_session_manager/
│   └── seamless_session_manager.cpp     # 无缝联机会话管理
├── cs/                                   # "CS" 子系统 (Co-op Seamless)
│   ├── session_manager.cpp
│   ├── menu_man.cpp
│   ├── lua_event_man.cpp
│   ├── lock_tgt_man.cpp
│   ├── world_chr_man.cpp
│   ├── map_item_man.cpp
│   ├── event_flag_man.cpp
│   ├── game_man.cpp
│   ├── fe_man.cpp
│   ├── game_data_man.cpp
│   └── emk_system.cpp
└── mod/
    ├── voice_chat.cpp                   # VoIP 语音聊天
    ├── preferences.cpp                  # 用户偏好设置
    ├── cheat_detection_spider.cpp       # 反作弊检测蜘蛛
    └── message_repository/
        ├── mod_message_repository.h
        └── locale.h
```

## 1.5 第三方库

| 库                   | 用途                   |
| ------------------- | -------------------- |
| **Steam SDK**       | Steam 网络 API、大厅管理    |
| **Google Crashpad** | 崩溃上报（本地 dump + 远程上传） |
| **libcurl**         | HTTP/HTTPS/FTP 网络通信  |
| **zlib 1.3.1**      | 数据压缩解压               |
| **nlohmann/json**   | JSON 解析              |
| **{fmt}**           | C++ 格式化库             |

---

# 二、保护机制

## 2.1 代码保护

- **Themida 3.x 商业加壳**（unlicense 检测确认）：核心安全逻辑（反调试、反篡改、反 dump）加密在 `.themida` 段内
- **反 Frida 检测**：Themida 3.x 内置，导致 unlicense OEP 追踪失效
- **CFG/XFG**：启用控制流保护，防御 ROP/JOP 攻击
- **导入表混淆**：IAT 被 Themida 隐藏，仅暴露 8 个导入项；实际运行时动态解析大量 Windows API，Themida 3.x 对大部分导入使用 wrapper 跳转

## 2.2 网络安全

- **SSL 公钥固定**：`"SSL public key does not match pinned public key"`，防中间人攻击
- **RSA 加密**：`rsa(n)` / `rsa(e)` 公钥参数存储于 `.rdata`
- **SHA256 哈希**：数据完整性校验
- **数字签名**：rsaEncryption、sha256WithRSAEncryption、sha512WithRSAEncryption

## 2.4 双壳保护：Themida + Arxan（2026-05-10 补充）

**ersc.dll 受到两层保护：**

| 层级 | 保护工具 | 保护对象 | 作用 |
|------|---------|---------|------|
| **DLL 层** | Themida 3.x | `ersc.dll` 自身 | 反调试、反 dump、代码加密、IAT 混淆 |
| **游戏进程层** | Arxan（现名 GuardIT） | `eldenring.exe` 的代码 | 反篡改、代码完整性校验、代码自动修复 |

> 来源：[Reversing Arxan (GuardIT)](https://me3.help/en/latest/blog/posts/arxan-reversing-1/)，作者为 me3 项目开发者。

**Arxan 的工作原理**（与我们的逆向直接相关）：

Yui 的 Seamless Co-op 需要在游戏代码中打"数百个 hook"。这些 hook 修改了受 Arxan 保护的函数。Arxan 通过定时器周期性检查被修改的代码区域，发现篡改后会：

1. 静默写标志位 → FromSoftware 用来封禁在线作弊者
2. 破坏栈/控制流使游戏崩溃（难以调试）
3. **自动修复被修改的代码**

Yui 的绕过方案：扫描定时器模式 → 把条件跳转 `JC` 改为无条件跳转 `JMP`，使校验永不执行。在 Elden Ring 中这种定时器模式非常规律（16.67ms 帧间隔倒计时，到期后调用 `arxan_code_restoration_check()`）。

**关键影响**：
- Frida 的 `Interceptor.attach()` 修改了 `.text` 代码，可能触发 Arxan（不仅是 Themida）的完整性校验
- x64dbg 的软件断点（`int3`）同样修改代码，在 Arxan 保护的区域内使用会立即崩溃
- 这就是我们动态追踪闪退的真正原因：**Themida + Arxan 双重检测**

## 2.3 反作弊

- **CSCheatDetectionSpider**：运行时检测内存补丁/修改
- **存档隔离**：使用独立存档，声明 `"It does not contain an anticheat"`（但内置 Spider 检测）

- **CSCheatDetectionSpider**：运行时检测内存补丁/修改
- **存档隔离**：使用独立存档，声明 `"It does not contain an anticheat"`（但内置 Spider 检测）

---

# 三、可分析层

## 3.1 导出与导入

### 3.1.1 导出函数：modengine_ext_init

| 序号  | 地址          | 名称                   |
| --- | ----------- | -------------------- |
| 1   | 0x180002b00 | `modengine_ext_init` |

该函数是 Mod Engine 2 加载 DLL 后的导出入口，接收一个 Mod Engine 扩展接口指针。它是 **Mod Engine 的桥接层**，不是游戏业务主循环：

1. 把全局扩展对象 `0x180215308` 写回宿主输出指针
2. 分配内部 `0x20` 字节回调上下文，注册回调入口 `0x180002c40`
3. vtable 方法 `0x180002ce0`（当 edx==1 时）：保存宿主传入的 rcx 到全局 `0x18021c020`，解析当前模块 PE 头，将 `AddressOfEntryPoint` 写入全局 `0x18021c028`
4. 入口地址验证为 PE Header 中的 `0x18030b380`
5. 后续包装函数通过 `call qword [0x18021c028]` 间接调用原始入口
6. vtable 中至少有一个槽位跳转到 `0x180028a30`，随后落入 Themida 保护区

**全局扩展对象 vtable**（位于 `0x180215308`，vtable `0x1801bbc60`）：

| 槽位     | 地址            | 职责                                                                    |
| ------ | ------------- | --------------------------------------------------------------------- |
| 析构     | `0x180002ca0` | 析构/释放方法                                                               |
| 启动     | `0x180002960` | 桥接启动：构造回调上下文，转调 OEP                                                   |
| banner | `0x180002cd0` | 返回 `"Elden Ring Seamless Co-op mod by Yui [ YuiKeyNexus Version 3 ]"` |

**0x20 字节回调上下文布局**：

| 偏移    | 内容                                    |
| ----- | ------------------------------------- |
| +0x08 | 字节状态位指针                               |
| +0x10 | 宿主上下文（来自 `0x18021c020`）               |
| +0x18 | 函数指针（静态值为 `0x180028a30`，落入 Themida 区） |

### 3.1.2 导入函数（可见 IAT）

由于 Themida 混淆，IAT 仅显示最小集（实际运行时动态解析远超此表）：

| DLL             | 函数                               |
| --------------- | -------------------------------- |
| kernel32.dll    | GetModuleHandleA                 |
| USER32.dll      | GetAsyncKeyState                 |
| steam_api64.dll | SteamAPI_GetHSteamPipe           |
| WS2_32.dll      | WSACleanup                       |
| ADVAPI32.dll    | BuildExplicitAccessWithNameW     |
| CRYPT32.dll     | CertAddCertificateContextToStore |
| WLDAP32.dll     | Ordinal_301                      |
| Normaliz.dll    | IdnToAscii                       |

> **运行时依赖**：`steam_api64.dll` 必须位于 DLL 同目录，否则 LoadLibrary 返回错误 126。
### 3.1.3 重建导入表（2026-05-10）

> 通过扫描  中 288 个  间接调用点，加载 DLL 后从运行时内存读取解密的 IAT 条目，再解析目标 DLL 的 PE 导出表匹配函数名。

#### 导入概览

| DLL | 函数数 | 主要用途 |
|-----|--------|---------|
| **WS2_32.dll** | 26 | Winsock 网络 I/O：socket/connect/send/recv 全套 |
| **WLDAP32.dll** | 18 | LDAP 目录服务：玩家注册/查找 |
| **KERNEL32.DLL** | 15 | 内存/线程/模块/同步 |
| **ntdll.dll** | 6 | 临界区 + CRT 堆分配 |
| **steam_api64.dll** | 1 | SteamAPI_GetHSteamUser |
| **ADVAPI32.dll** | 1 | CryptDestroyKey |

> ⚠️ **WLDAP32.dll 的 18 个 LDAP 函数是静态分析完全遗漏的模块**。原以为只依赖 Steam 做玩家匹配，实际还有一套 LDAP 目录服务用于玩家注册表/查找。

#### WS2_32.dll — 网络 I/O（26 函数）

| 函数 | 调用次数 | 类别 |
|------|---------|------|
| WSAGetLastError | 41 | 错误诊断 |
| ntohs | 20 | 字节序转换 |
| closesocket | 14 | 连接管理 |
| sendto | 9 | UDP 发送 |
| getsockname | 8 | 地址查询 |
| send | 8 | TCP 发送 |
| WSASetLastError | 6 | 错误设置 |
| bind | 6 | 端口绑定 |
| recv | 6 | TCP 接收 |
| setsockopt | 6 | 选项设置 |
| socket | 6 | 创建 socket |
| ntohl + getsockopt | 7 | 字节序转换 + 选项查询 |
| accept/connect/getpeername/listen | 8 | TCP 连接管理 |
| WSA 初始/清理/事件 | 4 | 框架支持 |
| select/gethostname/ioctlsocket | 3 | I/O 多路复用+信息 |

> 同时使用 TCP（send/recv/connect/accept/listen）和 UDP（sendto/recvfrom）。select + WSAAsync 事件模型。

#### WLDAP32.dll — LDAP 目录服务（18 函数）

| 函数 | 类别 |
|------|------|
| ldap_initA / ldap_sslinitA | 初始化连接（含 SSL） |
| ldap_bind_sA / ldap_simple_bind_sA | 认证绑定 |
| ldap_unbind_s | 断开 |
| ldap_search_sA | 搜索目录 |
| ldap_first_entry / ldap_next_entry | 遍历搜索结果 |
| ldap_first_attributeA / ldap_next_attributeA | 遍历条目属性 |
| ldap_get_dnA | 获取条目标识名 |
| ldap_get_values_lenA / ldap_value_free_len | 读取/释放属性值 |
| ldap_set_optionA | 设置 LDAP 选项 |
| ldap_memfreeA / ber_free / ldap_msgfree | 内存释放 |
| ldap_err2stringA | 错误消息 |

> **推测**：YuiKeyNexus3 使用 LDAP 协议做玩家注册表/匹配服务器。SSL 固定公钥（）用于 ldap_sslinitA 的 TLS 连接。

#### KERNEL32.DLL — 系统 API（15 函数）

| 函数 | 调用次数 | 类别 |
|------|---------|------|
| VirtualProtect | 221 | 🔴 Themida 解壳 |
| CloseHandle | 27 | 句柄管理 |
| GetProcAddress | 21 | 动态 API 解析 |
| GetCurrentThreadId | 10 | 线程 ID |
| GetModuleHandleA | 8 | 模块句柄 |
| Sleep | 7 | 延时 |
| FreeLibrary | 6 | 卸载 DLL |
| GetCurrentProcessId | 5 | 进程 ID |
| VirtualQuery | 4 | 内存查询 |
| HeapFree | 2 | 堆释放 |
| CompareStringW / FreeLibraryAndExitThread / GetTickCount / OpenThread / TlsGetValue | 各 1 | 杂项 |

#### ntdll.dll — 堆 + 临界区（6 函数）

| 函数 | 用途 |
|------|------|
| RtlAllocateHeap / RtlReAllocateHeap | 堆分配/重分配 |
| RtlInitializeCriticalSection / Enter / Leave / Delete | 临界区全生命周期 |

> 使用原生 NT 堆 API（非 malloc），临界区用于多线程同步。

#### steam_api64.dll + ADVAPI32.dll

| 函数 | 说明 |
|------|------|
| SteamAPI_GetHSteamUser | 获取 Steam 用户句柄（动态解析，不在可见 IAT） |
| CryptDestroyKey | 销毁加密密钥 |

> ⚠️ 仅找到 1 个加密相关导入。RSA/SHA256 可能使用静态链接库。

#### 内部 Themida Wrapper 热点

除外部 API 外，约 190 个 IAT 目标指向  内部（Themida wrapper）。前 5 热点：

| 地址 | 调用次数 |
|------|---------|
| ersc.dll+0x16F9A8 | 764 |
| ersc.dll+0x16C990 | 172 |
| ersc.dll+0x1707FC | 110 |
| ersc.dll+0x365CFC | 83 |
| ersc.dll+0x16E990 | 68 |

> 这些 wrapper 在 Themida 的  区域，运行时执行安全检查后跳转到真实 API。



## 3.2 架构分层

基于字符串、类名、调用链证据，将已解密 `.text` 逻辑划分为五层：

| 层级           | 直接证据                                                                                                           | 职责                                                                |
| ------------ | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **宿主桥接层**    | `modengine_ext_init`、`0x180215308`、`0x1801bbc60`                                                               | Mod Engine ↔ PE 入口连接                                              |
| **CS 管理器层**  | `CSSessionManager`、`CSGameMan`、`CSPartyMemberInfo`、`CSFeMan`、`game_man.cpp`                                    | 会话、队伍、前端/游戏状态编排                                                   |
| **平台/网络适配层** | `SteamSocketManager`、`SteamNetworking006`、`networking.cpp`、`YuiKeyNexus3`                                      | Steam / YuiNexus3 / 内部 networking 接入                              |
| **功能模块层**    | `voice_chat.cpp`、`cheat_detection_spider.cpp`、`battle_royale.cpp`、`spectate.cpp`、`buddy.cpp`、`preferences.cpp` | 语音（CSVoiceChatManager + 命令控制器）、反作弊（WhatIsPatchBytes）、观战、Buddy、大逃杀 |
| **壳区覆盖层**    | `"Steam lobby creation timed out"` 等主要回溯到 `0x1805...`                                                          | 用户可见大厅状态机 → Themida                                               |

联机会话 / 大厅管理并非最底层，而是 CS 管理器层与平台/网络适配层之间的**中枢业务带**。

## 3.3 联机会话中轴（核心分析区）

### 3.3.1 Session Registry：fcn.180026eb0

**身份确认**：函数内部在 `0x180026e6d` 直接引用 `OnBeJoinType (%u)` 字符串，确认参与 join type 诊断。

**核心逻辑**：从全局 session registry（`base + 0x10ef0`，`count + ptr-array` 结构）中按条件查找 session。

**匹配条件（按优先级）**：

1. **键值匹配**：`session + 0x580 → +0x950` 与输入 arg3 比较 → 命中返回 session
2. **vtable 匹配**：`session + 0x5b0` → vtable 函数 `+0x48` → 返回结果与 `arg2 + 0x218` 比较
3. **当前会话特殊路径**：候选 session == `[arg1_base + 0x1e508]` 时，走 `call [arg1 + 0xf0]` / `call [arg1 + 0xf8]` 二次验证

**返回值**：session 指针（命中）或 NULL（遍历结束未命中）。

**两个已知调用者**：

| callsite      | 所在上下文                | 用途                            |
| ------------- | -------------------- | ----------------------------- |
| `0x18008032a` | 0x180080250 簇（状态归约层） | 确认 session 存在后映射资源 ID         |
| `0x18008b652` | 0x18008b4c0 簇（裁决层）   | 查找 session 用于 join/be-join 判定 |

> 两个调用者都先通过 `call [obj + 0xe8]` 获取 session 标识，与 `0x10ee8` / `0x10f98` 比对后再进入 registry。

### 3.3.2 状态归约层：0x180080250 簇

属于 `CSGameMan` / `CSPartyMemberInfo` 模块（通过字符串引用交叉确认）。

**0x180080250（资源 ID 归约器）**：

```
// 入口：0x180080250
rdx = [rcx + 0x40]              // 读取管理器
rax = [rdx + 0x88]              // 读取内部状态结构
test [rax + 0x229], 0x40        // bit 6 标志检查
if zero: jmp [rax+0x160]        // 快速路径

// 非快速路径：0x1800802ad
edi = [rsi + 0x08]              // 活动条目状态索引
eax = edi & 0xf0000000          // 高 4 位掩码
ebx = 0x7fde60                  // 默认资源 ID（哨兵）
if eax != 0x10000000: goto exit // 不在游戏资源范围
// 扩展为 64 位 ID + 溢出检查
call [arg2_base + 0xe8]         // 获取 session 标识
cmp eax, [r14 + 0x10ee8]        // 比对 session ID 槽位 1
if eq: 直接用当前对象
cmp eax, [r14 + 0x10f98]        // 比对 session ID 槽位 2
if ne: 走备用路径
call fcn.180026eb0              // ★ 调用 session registry

// 资源 ID 映射：0x18008033b
// 状态索引 0..4 → 资源 ID 数组 {0x7fde61, 0x7fde62, 0x7fde63, 0x7fde64, 0x7fde65}
// 哨兵 0x7fde60 时：调用 fcn.1800a6f10 读取 0x3c 号参数表

// 高级资源选择：0x18008043d
edi = [rsi + 0x538]             // 深层状态字段
if edi < 0:
    rax = [rsi + 0x190]
    edi = [rax + 0xb8 + 0x44]   // 多层指针追踪
    // if edi == 0xfffffffe:
        // if [rsi+0x68] == 4: vtable 方法调用链
        // 检查 [rsi+0x532] bit 0x20
        // 选择 [rsi+0x20c] 或 [rsi+0x544]
```

**0x180080510（party member 遍历器）**：

```
rax = [rcx + 0x40] → [*] → [*] // 三次指针追踪
rdx = [rax + 0x1e508]           // "当前会话"引用（或 NULL）
rax = [rcx + 0x10]              // 活动条目列表
// 遍历 [rcx+0x10]+0x30 链表：
//   步长 0x28，比较 [entry+0x20] == edi，检查 [entry+0x19] == 0
//   cmovae 选中最优匹配
```

**0x180080610（CSGameMan 条件分发桩）**：

```
if r8d == 0x2595:               // 特殊游戏状态码
    验证对象层级链
    jmp [rcx+0x40+0xb8]         // 快速断言路径
else:
    [rcx+0x60] 通用处理链
```

> 该地址直接引用 `CSGameMan`、`CSPartyMemberInfo`、`game_man.cpp` 字符串。

### 3.3.3 Join / Be-Join 裁决层：0x18008b4c0 簇

**0x18008b4c0（字节级裁决器）**：

```
rsi = r8                        // 输出缓冲区
rdi = rdx                       // 目标对象
call [rax + 0x1a0]              // ★ 调用 this 的 0x1a0 回调
r15 = [r14 + 0x08]              // 第二级结构
r13 = [r14 + 0xa0] → [*]       // 读取 flags
rbp = [r15] → [*]               // session 基础对象
r12 = [rbp + 0x1e508]           // "当前会话"引用（或 NULL）

dl = 0x10                       // 默认返回值：0x10

// 基于 flags 的四路分支：
test r13d, 0x80000              // 特殊主机状态
  if set && r12 == rdi: → [rsi] = 0x10; return
test r13d, 0x20000              // → 复杂路径
test r13d, 0x40000              // → 二次判定路径
test r13d, 0x10000              // → 额外匹配路径

// 其中一条路径（0x20000 未命中）：
cmp eax, [rbp + 0x10f98]        // 比对 session ID
if match:
    call fcn.180026eb0          // ★ session registry
    if NULL: return 0x10
    if == r12:                  // 命中当前会话
        经过 0x5b0 vtable + [rdi+0x18] 链验证
        返回 0x10 / 0x06 / 0x1f
```

**关键特征**：

- flags 高位的语义映射：`0x10000` / `0x20000` / `0x40000` / `0x80000`
- 返回**字节级小枚举**（0x10、0x06、0x1f），不是布尔值
- 依赖 session registry 查找，自身负责将结果映射为裁决字节

**同簇其他成员**：

| 地址            | 角色                                                                |
| ------------- | ----------------------------------------------------------------- |
| `0x18008b7e0` | 布尔判定器：复用相同 session 匹配框架，结果喂给 `[ctx+0x1b0]`                        |
| `0x18008b960` | 后处理/应用层：键值排序查找 + `call [iface+0xb8/0xd0/0xd8]` + 写 `target+0x208` |

以上函数均位于 `fcn.18008b040` 这个大函数内部（约 407 个基本块）。

### 3.3.4 Active-Object Selector：fcn.180024bc0

- 遍历 `[rcx + 0x60]` 持有的活动条目
- 筛选 `flags & 0x202 == 2` 的对象
- 与全局 session registry 交叉匹配
- 命中后更新 `ctx + 0x58`：写入 `+0x1d4`、`+0x1f0` 等偏移
- 职责："从活动对象列表里选出当前目标会话/主机"的 selector

### 3.3.5 Join Type 分类器：fcn.180027020

- 接收 32 位输入值，返回 0/1/2/3 四档分类结果
- 使用 `0x10ee8` / `0x10f98` 全局标识
- 必要时走额外回调路径
- 与 `SprjSessionConnectType` 的绑定属于推断，缺少直接字符串锚点
- 无 direct call 命中 → 可能走壳区或间接调用链

### 3.3.6 调用关系总图

```
fcn.18008b040（407 BB，join/be-join 大函数）
  ├── 0x18008b4c0：字节裁决器
  │     ├── call [this+0x1a0]
  │     ├── test flags: 0x10000/0x20000/0x40000/0x80000
  │     ├── cmp [call+0xe8] with [session+0x10ee8/0x10f98]
  │     └── call fcn.180026eb0 ────────────┐
  ├── 0x18008b652：session 匹配点            │
  │     ├── cmp [call+0xe8] with [rbp+0x10f98]│
  │     └── call fcn.180026eb0 ────────────┤
  ├── 0x18008b7e0：布尔判定器                │
  │     └── → [ctx+0x1b0]                   │
  └── 0x18008b960：后处理/应用层              │
                                            │
fcn.18007f3c0（game_man/party 大函数）       │
  ├── 0x180080250：资源 ID 归约器            │
  │     ├── 状态索引 → {0x7fde60..0x7fde65}  │
  │     ├── 哨兵路径：fcn.1800a6f10(0x3c)    │
  │     ├── call [arg2+0xe8]                │
  │     ├── cmp [r14+0x10ee8/0x10f98]       │
  │     └── call fcn.180026eb0 ────────────┼── fcn.180026eb0
  ├── 0x180080510：party member 遍历器       │    (session registry)
  └── 0x180080610：CSGameMan 分发桩          │    内部引用
                                            │    "OnBeJoinType (%u)"
fcn.180024bc0（active-object selector）     │
  ├── 遍历 [rcx+0x60]                       │
  ├── 筛选 flags & 0x202 == 2               │
  └── → ctx+0x58                            │
                                            │
fcn.180027020（join type 分类器，0-3）       │
  └── 无 direct call，走间接/壳区             │
```

### 3.3.7 已确认全局数据结构

| 地址偏移             | 访问方式                                  | 含义                             |
| ---------------- | ------------------------------------- | ------------------------------ |
| `base + 0x10ee8` | `[session_obj + 0x10ee8]`             | 当前 session ID 槽位 1             |
| `base + 0x10f98` | `[session_obj + 0x10f98]`             | 当前 session ID 槽位 2             |
| `base + 0x10ef0` | `[rax + 0x10ef0]` → count + ptr-array | session registry 表             |
| `base + 0x1e508` | `[obj + 0x1e508]`                     | "当前会话"对象引用                     |
| `base + 0x1e538` | `[obj + 0x1e538]`                     | 备用会话引用                         |
| `0x180214680`    | 全局 XOR                                | 栈溢出保护 cookie                   |
| `0x1801d66b0`    | 静态数组                                  | 资源 ID 映射表 {0x7fde60..0x7fde65} |

### 3.3.8 模块归属确认

通过字符串引用交叉验证：

- **CSGameMan**（13 处）：`0x1800806a1`, `0x1800846ab`, `0x180084d5f`, `0x18008d173`, `0x18008d1a5`, `0x18008d40f`, `0x18008e3dc`, `0x18008ea84`, `0x18008f036`, `0x18008f754`, `0x18008f786`, `0x18008f7b8`, `0x18008fd48`
- **CSPartyMemberInfo**（6 处）：`0x1800806ba`, `0x180084d78`, `0x18008d18c`, `0x18008e3f5`, `0x18008f04f`, `0x18008f76d`
- **game_man.cpp**（20+ 处）：分布在 `0x18008xxxx` 区域
- **OnBeJoinType (%u)**（1 处）：`0x180026e6d`（位于 `fcn.180026eb0` 内部）

> **结论**：CSGameMan / CSPartyMemberInfo 代码主体在 `0x18008xxxx` 区域，session registry 是独立的 `0x18002xxxx` 区域函数，二者通过 `call` 互连。

## 3.4 通信架构

### 3.4.1 网络框架

- 基于 **SteamAPI** + **YuiKeyNexus V3** 自研 P2P 协议
- 大厅系统通过 Steam 匹配
- YuiKeyNexus3 管理联机会话、玩家状态同步

### 3.4.2 语音聊天

- 内置 VoIP，集成 YuiNexus3 音频系统
- 对象命名模式 `YuiNexus3VoiceChatAudioInputObj_%d`

### 3.4.3 崩溃上报

- Google Crashpad 框架
- 本地存储：`reports/` 目录（`metadata` + `settings.dat`）
- 支持远程上传（HTTP/FTP）

### 3.4.4 大逃杀模式

- 独立协议：**YuiKeyBattleRoyale2**
- 字符串：`"Unrecognised battle royale game mode: %u"`

## 3.5 语音聊天模块

### 3.5.1 代码定位

语音聊天代码集中在两个关键函数：

| 函数              | 地址          | 规模                           | 复杂度 | 角色                     |
| --------------- | ----------- | ---------------------------- | --- | ---------------------- |
| `fcn.1800a47a0` | 0x1800a47a0 | 1492 B, 259 instr, 10 BB     | 7   | Play/Stop 命令控制器        |
| `fcn.1800b0400` | 0x1800b0400 | 23,514 B, 4290 instr, 558 BB | 336 | CSVoiceChatManager 主入口 |

> `fcn.1800b0400` 是迄今发现最大的单个函数（558 个基本块），包含完整的音频对象生命周期管理。

### 3.5.2 fcn.1800a47a0：命令控制器

**调用者**：`fcn.180302a08 @ 0x1802fb0ef`（壳区 → 间接调用）。

**入口逻辑**：

```
0x1800a47d6: rax = [rcx + 0x18]              // 读取内部状态对象
0x1800a47da: test [rax + 0x229], 8           // bit 3 状态标志
if zero: goto cleanup                         // 状态未就绪，跳过
rsi = rcx                                     // 保存 this 指针（vtable 接口）
r13 = [*rcx]                                  // 读取 vtable → 第一个槽位（state obj）
if r13 == NULL: goto cleanup
cmp byte [r13 + 0xb68], 0                     // ★ 检查"活跃"标志
if != 0: goto cleanup                         // 已有活跃音频，跳过
call [rsi + 0x50]                             // vtable[10]：获取某对象
rax = call [*rax + 0x50](rcx, 0x118, 8)      // 分配 0x118 字节内部结构
rbx = rax                                     // 保存到 rbx
call fcn.18018aad0(rbx, 0, 0x118)             // 内存初始化
call [rsi + 0x70](rbx)                        // vtable[14]：初始化音频设备
```

**Play / Stop 双路径**：

```
// 路径 A：Stop_VoiceChat
0x1800a4963: lea rdx, "Stop_VoiceChat"
0x1800a4975: call [rsi + 0x88]               // vtable[17]：格式化为命令结构
// ... 构造局部数据 ...

// 路径 B：Play_VoiceChat
0x1800a49b5: lea rdx, "Play_VoiceChat"
0x1800a49c4: call [rsi + 0x88]               // vtable[17]：格式化为命令结构
// ... 构造局部数据 ...

// 公共执行路径：
0x1800a4a03: call [rsi + 0x90](rcx, 0x10000, 0x80, r15)  // vtable[18]：创建音频对象
0x1800a4a21: call [rsi + 0x60]               // vtable[12]：获取管理器引用
0x1800a4a2a: call rbx                          // ★ 调用管理器方法执行命令
0x1800a4a2f: cmp eax, 1                       // 检查返回值
if ne: goto error_path

// 成功路径：
0x1800a4c7d: mov byte [r13 + 0xb68], 1       // ★ 设置活跃标志

// 失败路径：
0x1800a4d44: lea "Unable to create YuiNexus3 player audio object instance [%u] [error = %u]"
0x1800a4d59: call fcn.18001b980               // 格式化错误消息
0x1800a4d5e: lea "ersc\\mod\\voice_chat\\voice_chat.cpp"
0x1800a4d6e: call fcn.180028800               // 断言失败 → int3
```

**vtable 接口布局**（rsi 指向的 this 对象）：

| 偏移      | 调用点                | 推测含义                    |
| ------- | ------------------ | ----------------------- |
| `+0x50` | `0x1800a4807`      | 获取音频设备/上下文对象            |
| `+0x60` | `0x1800a4a21`      | 获取管理器/调度器引用             |
| `+0x70` | `0x1800a483d`      | 初始化音频设备                 |
| `+0x88` | `0x1800a4975/49c4` | 格式化命令字符串为内部结构           |
| `+0x90` | `0x1800a4a0c`      | 创建 YuiNexus3 音频对象       |
| `+0x98` | `0x1800a4a12`      | 管理器方法指针（随后 call rbx 执行） |
| `+0xa0` | `0x1800a4a51`      | 获取/设置音频会话状态             |
| `+0x58` | `0x1800a4c7a`      | 音频对象清理/释放               |

**状态对象（r13）关键字段**：

| 偏移       | 用途                                   |
| -------- | ------------------------------------ |
| `+0xb48` | 音频状态结构体（0x118 字节，由调用参数 edx=0x118 确认） |
| `+0xb68` | **活跃标志**（byte）：0 = 空闲，1 = 音频激活中      |

### 3.5.3 fcn.1800b0400：CSVoiceChatManager

- 23,514 字节、558 基本块、336 圈复杂度
- 栈帧 2048 字节、187 局部变量、238 被调用者
- 1 个 in-degree（单一入口），符合管理器主循环/事件处理特征
- 直接引用 `CSVoiceChatManager@CS@@` 和 `VoiceChatSteam@DLNR3D@@` 字符串
- 基于规模和行为判断：此函数负责**全部音频对象生命周期**，包括创建、Steam 网络发送/接收、缓冲管理、多人混音等

### 3.5.4 语音聊天架构总结

```
游戏 Lua/命令系统
  │ "Play_VoiceChat" / "Stop_VoiceChat"
  ▼
fcn.1800a47a0（命令控制器，10 BB）
  │ 解析命令 → vtable 调用 → 创建 YuiNexus3 音频对象
  │ 设置 [state+0xb68] = 1（活跃标志）
  ▼
fcn.1800b0400（CSVoiceChatManager，558 BB）
  │ 音频对象生命周期管理
  │ Steam VoiceChatSteam 网络接入
  │ 多人音频缓冲/混音/发送
  ▼
YuiKeyNexus3 网络层 → Steam
```

## 3.6 反作弊蜘蛛

### 3.6.1 代码定位

反作弊蜘蛛代码位于 `fcn.1800289c0`（一个超大型初始化函数）内部，三个引用点均在 `+0x1a18`、`+0xcaa5`、`+0xcac7`、`+0xcad5`、`+0xcaed` 偏移处。

### 3.6.2 核心逻辑片段

```
0x180038a2c: lea rcx, "Unable to read image info"
0x180038a33: lea rdx, "ersc\\mod\\cheat_detection_spider\\cheat_detection_spider.cpp"
0x180038a3a: mov r8d, 6                         // 源文件第 6 行
0x180038a40: call fcn.180028800                   // 断言失败处理
// → 如果读取镜像信息失败，直接 crash

0x180093c48: lea rcx, "CSCheatDetectionSpider::WhatIsPatchBytes() runtime exception - This is not a PatchByte() function"
```

### 3.6.3 行为推断

- **WhatIsPatchBytes()**：检查某地址是否属于合法的 PatchByte 函数
- **镜像信息读取**：读取游戏进程的 PE 镜像信息（验证完整性？）
- 失败策略是**直接 crash**（int3 断言），而非静默绕过
- 这解释了 mod 声明 `"It does not contain an anticheat"` 与内置 Spider 检测的矛盾：蜘蛛检测的是**其他**玩家的作弊行为，而非自身

## 3.7 网络适配层

### 3.7.1 fcn.1800202e0：核心网络函数

| 属性   | 值                                 |
| ---- | --------------------------------- |
| 地址   | 0x1800202e0                       |
| 规模   | 1430 B, 342 instr, 74 BB          |
| 复杂度  | 49（圈复杂度）                          |
| 调用者  | 10 个                              |
| 被调用者 | 26 个                              |
| 参数   | 5 个（rcx, rdx, r8, r9, [rsp+0x28]） |
| 递归   | 是（自调用）                            |

该函数引用 `ersc\networking\networking.cpp` 字符串，10 个调用者表明它是网络层的通用入口。递归属性暗示它可能处理网络包的分片/重组。

### 3.7.2 fcn.1800a6550：跨模块消息派发

- 在 `map_item_man.cpp`、多个 `0x18008...` / `0x18009...` 调用点重复出现
- 更像一层**跨模块消息/记录派发基础设施**，不专属于 lobby

### 3.7.3 SoloParamRepository

三个 helper 函数均引用 `SoloParamRepository` 字符串：

| 函数              | 地址          | 角色                          |
| --------------- | ----------- | --------------------------- |
| `fcn.1800a6f10` | 0x1800a6f10 | 读取参数表（被 0x180080250 哨兵路径调用） |
| `fcn.1800a7090` | 0x1800a7090 | 参数查询/验证                     |
| `fcn.1800a7240` | 0x1800a7240 | 参数写入/更新                     |

这些函数构成一个**参数仓库系统**，为上层管理器提供按索引号（如 0x3c）查询游戏参数的能力。在 0x180080250 的哨兵路径中，当 session 未命中时，会通过 `fcn.1800a6f10(0x3c)` 读取默认参数。

## 3.8 YuiKeyNexus3 协议层

### 3.8.1 协议消息一览

从字符串中提取的 YKNX3 协议操作码：

| 操作码                                 | 含义          |
| ----------------------------------- | ----------- |
| `YKNX3: OnBeJoinStart_EvilWanderer` | 加入邪恶流浪者     |
| `YKNX3: OnBeJoinStart_Wanderer`     | 加入普通流浪者     |
| `YKNX3_INVADERPRESENT`              | 入侵者存在       |
| `YKNX3_GIVEEMBERINSUFFECIENT`       | 余烬不足        |
| `YKNX3_PLAYERDISCONNECT`            | 玩家断线        |
| `YKNX3_BREAKINPLAYERMISSIONSUCCESS` | 入侵玩家任务成功    |
| `YKNX3_INFORMTOGGLEPVPTEAMS`        | 通知切换 PvP 队伍 |
| `YKNX3_INVASIONRADIUSERROR`         | 入侵半径错误      |
| `YKNX3_EVERGAOLRADIUSERROR`         | 永恒监狱半径错误    |
| `YKNX3_INVASIONSTATEERROR`          | 入侵状态错误      |
| `YKNX3_INFORMBEGINSPECTATEPLAYER`   | 通知开始观战      |
| `YKNX3_INFORMTOGGLEPVP`             | 通知切换 PvP    |
| `YKNX3_PLAYERBONFIRSTFIRSTLVLUP`    | 玩家篝火首次升级    |
| `YKNX3_PLAYERBONFIREWARP`           | 玩家篝火传送      |
| `YKNX3_INVASIONRAPIDREENTRYINFO`    | 入侵快速重入信息    |
| `YKNX3_BREAKINPLAYERJOIN`           | 入侵玩家加入      |
| `YKNX3_BREAKINSEARCH`               | 入侵搜索        |
| `YKNX3 dialogue [%u]`               | 对话消息        |

### 3.8.2 协议推断

- YKNX3 是作者自研的 P2P 应用层协议，运行在 Steam 网络层之上
- 操作码分为几大类：
  - **联机状态**：`OnBeJoinStart_*`、`PLAYERDISCONNECT`、`BREAKINPLAYERJOIN`
  - **PvP/入侵**：`INVADERPRESENT`、`INVASION*`、`BREAKIN*`、`TOGGLEPVP*`
  - **观战**：`INFORMBEGINSPECTATEPLAYER`
  - **篝火/传送**：`PLAYERBONFIRE*`
  - **通用**：`dialogue`
- 这些消息引用主要回溯到 `0x18008xxxx` 区域（CS 管理器层），说明 CS 管理器层负责 YKNX3 消息的序列化/反序列化

## 3.9 其他 CS 子模块

以下模块的源码文件字符串存在于 `.rdata`，但当前静态分析尚未深入追踪其具体函数：

| 模块             | 源文件路径                                       | 推测职责               |
| -------------- | ------------------------------------------- | ------------------ |
| menu_man       | `ersc\cs\menu_man\menu_man.cpp`             | 游戏内菜单管理            |
| lua_event_man  | `ersc\cs\lua_event_man\lua_event_man.cpp`   | Lua 事件桥接（脚本 ↔ C++） |
| lock_tgt_man   | `ersc\cs\lock_tgt_man\lock_tgt_man.cpp`     | 锁定目标管理             |
| world_chr_man  | `ersc\cs\world_chr_man\world_chr_man.cpp`   | 世界角色管理             |
| map_item_man   | `ersc\cs\map_item_man\map_item_man.cpp`     | 地图物品管理             |
| event_flag_man | `ersc\cs\event_flag_man\event_flag_man.cpp` | 事件标志管理             |
| fe_man         | `ersc\cs\fe_man\fe_man.cpp`                 | FE（前端）管理器          |
| game_data_man  | `ersc\cs\game_data_man\game_data_man.cpp`   | 游戏数据管理             |
| emk_system     | `ersc\cs\emk_system\emk_system.cpp`         | EMK 系统             |

> 这些模块的代码分散在 `0x18008xxxx` ~ `0x18009xxxx` 区域，与 game_man 和 session_manager 共享调用链。未来可以按需选取特定模块深入追踪。

### 3.9.1 CS 子模块引用密度扫描（2026-05-10）

通过每个模块源文件路径字符串的交叉引用数量评估代码可见度：

| 模块                 | 引用密度 | 优先级          | 主要分布                                          |
| ------------------ | ---- | ------------ | --------------------------------------------- |
| **game_data_man**  | 35   | 🔴 最高        | `fcn.180022210`、`fcn.18030c79a`、`0x180080xxx` |
| **event_flag_man** | 26   | 🔴 最高        | `fcn.1800202e0`（核心网络函数）、`fcn.180020940`       |
| fe_man             | 7    | 🟡 中         | 集中在 `0x18008xxxx` 区域                          |
| menu_man           | 5    | 🟡 中         | 集中在 `0x18008xxxx` 区域                          |
| map_item_man       | 4    | 🟡 中         | 跨 `0x18008/09xxxx` 区域                         |
| lua_event_man      | 2    | 🟢 低（但战略价值高） |                                               |
| lock_tgt_man       | 1    | 🟢 低         |                                               |
| world_chr_man      | 1    | 🟢 低         |                                               |
| emk_system         | 1    | 🟢 低         |                                               |

> 关键发现：**event_flag_man 的 26 个引用点中有 3 个在核心网络函数 `fcn.1800202e0` 内部**，说明事件标志系统与网络同步层紧耦合。game_data_man 的引用分散在多个区域，说明它是跨模块的基础设施。

## 3.10 初始化路径确认

### 3.10.1 桥接层跳转目标

静态反汇编揭示：`0x180028a30`（桥接层回调入口）的实际内容是：

```
0x180028a30: jmp 0x180243a89    ← 跳入 .themida 壳区
```

跳转目标 `0x180243a89` 位于 `.themida` 段内。从 `0x180028a35` 开始的后续字节是垃圾数据（`invalid` 指令、随机跳转），不是有效代码。

### 3.10.2 代码识别空白区

radare2 在 `0x180028a30` ~ `0x18003cc2f` 之间约 83KB 范围内**未能识别任何函数**。这个区域包含：

- cheat_detection_spider 的字符串引用（`0x180038a33` 等）
- 多个大函数的调用者（`0x18002a603`、`0x18002a940`、`0x18002cbf0`）
- 可能的 Themida stub / API wrapper 代码

### 3.10.3 结论

**DLL 的完整初始化序列无法通过纯静态分析还原**。桥接层 → `.themida` → 各管理器初始化的完整路径需要在动态调试中追踪。

但已发现的三个超大函数提供了重要线索：

| 函数              | 规模                | 调用者                   | 推测          |
| --------------- | ----------------- | --------------------- | ----------- |
| `fcn.18003cc30` | 24,378 B / 512 BB | `0x18002cbf0`（nofunc） | 可能的主初始化编排器  |
| `fcn.180096960` | 10,647 B / 426 BB | `0x18002a940`（nofunc） | 游戏逻辑主循环/状态机 |
| `fcn.18009d450` | 15,699 B / 476 BB | `0x18002a603`（nofunc） | 第二个大面积游戏逻辑  |

这三个函数是 `.text` 中最大的单函数，后续动态追踪应优先在这些函数的入口设断点。

## 3.11 动态追踪结果（2026-05-10）

> 通过 Frida 注入 Elden Ring 进程（Seamless Co-op Mod 环境），对 13 个关键函数进行运行时 hook。
> 游戏在联机初始化阶段（大厅浏览/连接建立期间）闪退，但捕获了约 1 秒的有效数据。

### 3.11.1 函数触发情况

| 函数 | 地址 | 是否触发 | 分析 |
|------|------|---------|------|
| **Join_ByteDecide** | 0x18008b4c0 | ✅ 高频（10+ 次/秒） | 游戏启动后立即触发，迭代不同连接对象 |
| **Join_BoolDecide** | 0x18008b7e0 | ✅ 1 次 | 在 ByteDecide 之间触发，返回 0xfc2a1501 |
| **NetCore** | fcn.1800202e0 | ✅ 3 次 | 事件码 rdx=0x803, 0x804, 0x7ee |
| **VoiceChat** | 0x1800a47a0 | ✅ 1 次（轻量版） | 语音模块初始化 |
| **SessionRegistry** | fcn.180026eb0 | ❌ 未触发 | 会话查找发生在玩家主动操作时 |
| **Init_Orch** | fcn.18003cc30 | ❌ 未触发 | 初始化已在此次运行前完成 |
| **GameLogic_Main** | fcn.180096960 | ❌ 未触发 | 可能在主菜单后才激活 |

### 3.11.2 JoinDecide 运行时数据

```
rcx = 0x72ce9ff4c0  (this 指针，堆分配，两次运行不一致)
rdx = 多个不同的目标对象指针：
  0x7ff3fc2a1510, 0x7ff3f6a95cb0, 0x7ff3f6a9c550,
  0x7ff3f6aa9690, 0x7ff3f6c48ec0, 0x7ff3fc430190  ...
r8  = 输出缓冲区指针（变化）
r9  = 0x18008b4b0 (函数内部固定引用地址)
```

**结论**：JoinDecide 在遍历一个连接/玩家列表（rdx 不断变化），对每个条目做 join 裁决。这是游戏启动后最早触发的业务函数之一。

### 3.11.3 NetCore 运行时数据

```
rcx = 0x72ce9fdb68  (this 指针，与 JoinDecide 的 this 不同)
rdx = 0x803 (2051), 0x804 (2052), 0x7ee (2030)  ← 事件/操作码
r8  = 0x0, 0x0, 0x1  (标志位)
返回 = 0x0, 0x0, 0x1 (前两次失败/未处理，第三次成功)
```

**推论**：
- rdx 值是网络事件类型码（纯整数枚举，非字符串指针）
- 调用序列 0x803 → 0x804 → 0x7ee 构成一个初始化握手流程
- fcn.1800202e0 是网络事件分发器：根据事件码路由到不同处理逻辑

### 3.11.4 闪退原因

- Themida 3.x 检测到 `Interceptor.attach()` 的内存 patch
- 更重要的：**Arxan 检测到游戏代码被修改**（Frida 在 Elden Ring 进程空间内操作，触发了第二层保护）
- 后续可尝试 Stalker（指令追踪，不 patch 代码）或硬件断点

### 3.11.5 改进的动态追踪方案

**发现：ModEngine 2 内置了 ScyllaHide 支持。**

在 `config_eldenring.toml` 中：

```toml
[extension.scylla_hide]
enabled = true    # 改为 true 即可启用
```

启用后，ModEngine 2 会在启动游戏时自动注入 ScyllaHide，绕过 Arxan 的反调试检测。之后可以直接用 x64dbg attach 到 `eldenring.exe` 进程，在 `ersc.dll` 的函数上设断点。

**操作步骤**：
1. 修改 Mod Engine 2 的 `config_eldenring.toml`，启用 `scylla_hide`
2. 通过 Mod Engine 2 启动 Elden Ring
3. x64dbg → File → Attach → 选择 `eldenring.exe`
4. 在 `ersc.dll` 模块中设断点（`ersc.dll + 0x26eb0` 等）
5. 在游戏中触发联机操作

**为什么要用这个方案而不是 Frida**：
- ScyllaHide 是专门针对 Arxan/Themida 的反反调试插件，Frida 不是
- ModEngine 2 已经在游戏启动时注入了 ScyllaHide，绕过了第一波反调试检测
- x64dbg 的硬件断点（DR0-DR3，4 个）不修改代码，不会被完整性校验检测到

### 3.11.6 外部参考资料

| 来源 | 内容 | 与我们工作的关系 |
|------|------|----------------|
| [Reversing Arxan (GuardIT)](https://me3.help/en/latest/blog/posts/arxan-reversing-1/) | Arxan stub 结构、定时器校验机制、dearxan 工具 | 解释了闪退根因，提供了彻底的 Arxan 绕过方案 |
| [boblord14/SeamlessCoopExtension](https://github.com/boblord14/SeamlessCoopExtension) | 基于 Seamless Co-op 的自定义游戏模式扩展，含 Cheat Engine 表 + DLL 脚本 | 有对 ersc.dll 的 hook 和内存读写代码，可直接参考地址 |
| [soulsmods/ModEngine2](https://github.com/soulsmods/ModEngine2) | Mod Engine 2 源码，含扩展/插件系统和 ScyllaHide 集成 | 解释了 `modengine_ext_init` 的完整宿主环境 |
| [ersc-docs.github.io](https://ersc-docs.github.io/) | Yui 的官方文档 | 安装和 Mod 兼容性指南 |

## 3.12 SeamlessCoopExtension 源码分析（2026-05-10）

> 来源：[boblord14/SeamlessCoopExtension](https://github.com/boblord14/SeamlessCoopExtension)，本地 clone 后分析 C++ 代码。

### 3.12.1 AOB 签名（可直接用于后续动态调试）

该项目通过 AOB 模式扫描在 `eldenring.exe` 中定位关键函数：

| 函数 | AOB 签名 | 用途 |
|------|---------|------|
| WorldChrMan | `48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0F 48 39 88` | 世界角色管理器全局指针 |
| GameMan | `48 8B 05 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? 0D 0F 94 C0 C3` | 游戏管理器全局指针 |
| EventFlagManager | `48 8B 3D ?? ?? ?? ?? 48 85 FF ?? ?? 32 C0 E9` | 事件标志管理器全局指针 |
| spEffectApply | `48 8B C4 48 89 58 08 48 89 70 10 57 48 81 EC ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 48 8B F1 0F 28 0D ?? ?? ?? ?? 48 8D 48 88` | 特殊效果应用函数 |
| entityID→ChrIns | `48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 41 56 48 83 ec ?? 48 8b 3d ?? ?? ?? ?? 33 db 49 8b f0 4c 8b f1 48 85 ff` | 实体 ID 转角色实例 |
| damageApply | `4C 8B DC 55 53 56 57 41 56 41 57 49 8D 6B 88 48 81 EC 48 01 00 00` | 伤害计算函数 |

### 3.12.2 游戏数据结构（交叉验证）

**WorldChrMan 玩家数组**：

```
[WorldChrMan + 0x10EF8] → PlayerArray[]
  PlayerArray[slot] (步长 0x10):
    +0x00: ChrIns* playerIns
    +0x08: unknown
```

> ⚠️ 注意：此处的 `0x10EF8` 是 WorldChrMan 对象内部的指针偏移，与我们在会话语境中看到的 `[session_obj + 0x10EE8]` 和 `[session_obj + 0x10F98]` 是**不同的基对象和不同的语义**。

**玩家属性链**（从 PlayerArray[0] 开始）：

| 属性 | 指针链 | 类型 |
|------|--------|------|
| HP | +0x10EF8 → [0] → +0x190 → +0x138 | int |
| MaxHP | +0x10EF8 → [0] → +0x190 → +0x13C | int |
| Idle Animation | +0x10EF8 → [0] → +0x190 → +0x58 → +0x18 | int |
| Current Animation | +0x10EF8 → [0] → +0x190 → +0x58 → +0x20 | int |
| X Position | +0x10EF8 → [0] → +0x190 → +0x68 → +0x70 | float |
| Y Position | +0x10EF8 → [0] → +0x190 → +0x68 → +0x78 | float |
| Z Position | +0x10EF8 → [0] → +0x190 → +0x68 → +0x74 | float |
| iFrames | +0x10EF8 → [slot] → +0x190 → +0x8 → +0x40 bit 1 | bool |

**ChrIns 结构**：

| 偏移 | 类型 | 含义 |
|------|------|------|
| +0x178 | CSSpecialEffect* | 特殊效果容器 |
| +0x1E8 | int | Entity ID（感谢 dasaav） |

**GameMan**：

| 偏移 | 含义 |
|------|------|
| [GameMan + 0xD60] + 0x1C（或 0x14） | 当前会话玩家数量 |

### 3.12.3 可复用的技术

- **MinHook**：项目使用 MinHook 库做函数 detour，证实绕过了 Arxan
- **PointerChain**：模板化的多级指针遍历工具，可复用于 Cheat Engine 脚本
- **Entity ID 体系**：Host 玩家的 Entity ID 固定为 10000，其他玩家为 10001+
- **事件标志**：使用自定义 EventFlag ID `1024622001` 做复活标记

## 3.13 社区逆向资源汇总（2026-05-10）

> 以下是通过全网搜索收集的 Elden Ring 逆向工程关键资源。

### 3.13.1 CT-TGA（The Grand Archives Cheat Table）

**来源**：[The-Grand-Archives/Elden-Ring-CT-TGA](https://github.com/The-Grand-Archives/Elden-Ring-CT-TGA)

最全面的 Elden Ring Cheat Engine 表，含完整的内存结构文档。**直接确认了我们分析的全局偏移**：

| 偏移 | 对象 | 含义 | 与我们分析的关系 |
|------|------|------|---------------|
| `WorldChrMan + 0x1E508` | 指针 | 本地玩家实例 | ✅ 我们在 ersc.dll 分析中多次看到此偏移作为"当前会话"引用 |
| `WorldChrMan + 0x10EF8` | 指针 | NetPlayers 列表（多人角色） | ⚠️ 在 ersc.dll 中这是 WorldChrMan 内部的数组指针，与会话对象中的 `0x10EE8` 不是同一个东西 |

CT-TGA 还记录了完整的游戏内存层次：GameDataMan → PlayerGameData → EquipInventoryData → InventoryItem（含 itemId、quantity 等偏移）。

**Seamless Co-op 事件标志修复**（CT-TGA 的独立模块）：
用于修复联机中任务进度不同步问题的具体 Flag ID：
- Ranni 任务：`1034509410`, `1034509412`, `1034509355-1034509358`, `1034509205`, `1034509305-1034509306`, `1034509417`, `1034500734`, `1034509416`, `1034500739`

### 3.13.2 libER — Elden Ring API 库

**来源**：[Dasaav-dsv/libER](https://github.com/Dasaav-dsv/libER)

C++ API 库，利用 Elden Ring 使用 MSVC 2015（最早的 ABI 兼容 MSVC 版本）的特点，提供类型安全的游戏接口：

- **Dantelion2 引擎命名空间**：DLKR（内核/同步）、DLRF（运行时类型反射）、DLSY（系统属性）、DLTX（字符串）、DLUT（工具）、DLIO（文件 I/O）
- **自定义内存分配器替换**：无需 hook 即可替换游戏分配器 → 与我们在源码树中看到的 `game_memory_unlimiter.cpp` 直接对应
- **非侵入式修改**：不通过代码 patch，无法被 Arxan 检测到
- 支持按游戏版本自动更新符号定义

### 3.13.3 网络架构演进确认

Yui 的 changelog 记录了网络层的两次重大重写：

| 版本 | 日期 | 变更 |
|------|------|------|
| **v1.2.0** | 2022.06 | "重写 Elden Ring P2P 系统，从废弃的 SteamNetworking 升级到新的 SteamNetworkingMessages API" |
| **v1.7.2** | 2024.06 | "完全重写代码……事件标志正确同步、匹配验证：只有相同 Mod 的玩家可以互联" |

这解释了我们在 ersc.dll 中同时看到 `SteamNetworking006`（旧）和 `SteamNetworkingMessages002`（新）字符串的原因——v1.2.0 后同时兼容两套 API。

### 3.13.4 NightFyre/EldenRing-SDK

**来源**：[NightFyre/EldenRing-SDK](https://github.com/NightFyre/EldenRing-SDK)

简化的 Elden Ring SDK，提供全局指针初始化：
```cpp
HEXINTON::InitSDK("EldenRing.exe", gGameMan, gGameDataMan, gWorldCharMan);
auto world = *HEXINTON::CGlobals::GWorldCharMan;
```

可结合我们的 AOB 签名替换其内部偏移，实现自动化地址解析。

---

# 四、不可分析层（.themida）

## 4.1 壳区覆盖范围

`.themida` 段：5,529,600 字节（总文件 71%），熵值 6.52，加密混淆。

## 4.2 已知加密内容

- 反调试/反篡改代码
- SSL 固定公钥的具体值
- RSA 密钥参数的具体值
- 网络通信加密算法细节
- 反作弊蜘蛛的检测逻辑（部分）
- 联机会话中建房/搜房超时、找不到房间等用户态大厅状态机（主要分支）
- 游戏版本签名的具体字节模式

## 4.3 突破路径

| 方案       | 工具                  | 可行性          | 详情                                |
| -------- | ------------------- | ------------ | --------------------------------- |
| 动态调试脱壳   | x64dbg + ScyllaHide | ✅ 已安装        | 见 `unpack_guide.md`               |
| 自动化脚本    | headless.exe + 脚本   | ⚠️ 未测试       | 见 `unpack_ersc.txt`               |
| 静态去混淆    | themida-unmutate    | 中，仅处理代码变异    | GitHub: ergrelet/themida-unmutate |
| 运行时 hook | 自定义 Frida 脚本        | 中，需绕过反 Frida | Frida 已安装                         |

###  4.3.1 unlicense 尝试记录

```
# 检测结果
INFO - Detected packer version: 3.x
DEBUG - Probed .text section at (0x1000, 0x18c626)
ERROR - Original entry point wasn't reached before timeout
```

**失败原因**：Themida 3.x 在 DLL 加载期间，所有解壳逻辑在 `.themida` 段内运行，不跳转到 `.text` 段。DLL 的"真实入口"是 DllMain，本身就是 Themida 壳代码。`dump_utils.py` 的 `probe_text_sections()` 刻意排除了 `.themida` 段。

### 4.3.2 内存 Dump 实验

通过 Python ctypes LoadLibrary 加载后：

1. `.text` 段代码未被加密，正常可读
2. pyscylla 成功 dump 进程内存（`ersc_dumped.exe`）
3. Dump 文件本质与原 DLL 相同，未做 IAT 修复和段清理

### 4.3.3 OEP / 导出入口关系

- `0x18030b380`：PE Header 中的 `AddressOfEntryPoint`
- `modengine_ext_init`（`0x180002b00`）：Mod Engine 调用的导出桥接层，非 OEP 本身
- 桥接层在运行时解析 PE 头，将 `0x18030b380` 保存到全局 `0x18021c028`
- 即使捕获到 `0x18030b380`，也不能等同于"脱壳后的真实 OEP"，因为后续实现可能继续跳入 Themida 保护代码

---

# 五、关键字符串

## 5.1 UI 消息

| 消息                                                                                   | 说明       |
| ------------------------------------------------------------------------------------ | -------- |
| `"You have been blocked by the host of the session"`                                 | 被房主踢出    |
| `"You have blocked the host of the session"`                                         | 已屏蔽房主    |
| `"This mod uses a separate save and does not connect to the matchmaking servers..."` | 用户免责声明   |
| `"Seamless Coop %s - Fatal Error"`                                                   | 致命错误弹窗标题 |
| `"No such pattern... The mod may not be compatible with the installed game version"` | 签名扫描失败   |

## 5.2 网络 / 服务器

| 字符串                                                    | 说明          |
| ------------------------------------------------------ | ----------- |
| `"crash server failed to launch, self-terminating"`    | 崩溃上报服务器启动失败 |
| `"crash server did not respond, self-terminating"`     | 崩溃上报服务器无响应  |
| `"Server denied you to change to the given directory"` | FTP 目录切换被拒  |

## 5.3 反作弊

| 字符串                                          | 说明                  |
| -------------------------------------------- | ------------------- |
| `CSCheatDetectionSpider::WhatIsPatchBytes()` | 非法 PatchByte 调用检测   |
| `"Unable to read image info"`                | PE 镜像验证失败（直接 crash） |
| `"Not a valid signature type"`               | 签名类型验证失败            |

## 5.4 YKNX3 协议消息

| 操作码                                                       | 类别     |
| --------------------------------------------------------- | ------ |
| `YKNX3: OnBeJoinStart_Wanderer` / `_EvilWanderer`         | 联机状态   |
| `YKNX3_PLAYERDISCONNECT`                                  | 联机状态   |
| `YKNX3_BREAKINPLAYERJOIN` / `_SEARCH` / `_MISSIONSUCCESS` | PvP/入侵 |
| `YKNX3_INVADERPRESENT` / `_INVASION*` / `_EVERGAOL*`      | PvP/入侵 |
| `YKNX3_INFORMTOGGLEPVP` / `_TOGGLEPVPTEAMS`               | PvP/入侵 |
| `YKNX3_INFORMBEGINSPECTATEPLAYER`                         | 观战     |
| `YKNX3_PLAYERBONFIREWARP` / `_FIRSTLVLUP`                 | 篝火/传送  |
| `YKNX3_GIVEEMBERINSUFFECIENT`                             | 通用     |
| `YKNX3 dialogue [%u]`                                     | 通用     |

## 5.5 语音聊天

| 字符串                                                                           |
| ----------------------------------------------------------------------------- |
| `Play_VoiceChat`                                                              |
| `Stop_VoiceChat`                                                              |
| `YuiNexus3VoiceChatAudioInputObj_%d`                                          |
| `"Unable to create YuiNexus3 player audio object instance [%u] [error = %u]"` |
| `CSVoiceChatManager@CS@@`                                                     |
| `VoiceChatSteam@DLNR3D@@`                                                     |
| `VoiceChatMemberRefInfo@DLNR3D@@`                                             |

---

# 六、工具链与附属文件

| 文件                   | 说明                                    |
| -------------------- | ------------------------------------- |
| `ersc.dll`           | 原始加壳样本（7.79 MB）                       |
| `ersc_dumped.exe`    | pyscylla 内存 dump（含 .themida，IAT 未修复）  |
| `ersc_functions.txt` | 2620 个函数列表（34 KB）                     |
| `ersc_strings.txt`   | 6061 条字符串完整列表（431 KB）                 |
| `steam_api64.dll`    | 运行时依赖                                 |
| `loader.c`           | C DLL 加载器                             |
| `dump_ersc.py`       | Python 加载 + 信号等待外部 dump               |
| `dump_direct.py`     | Python 加载 + pyscylla 内存 dump          |
| `trace_themida.py`   | Frida LdrLoadDll + 异常监控               |
| `unpack_ersc.txt`    | x64dbg 自动脱壳脚本                         |
| `unpack_guide.md`    | 手动脱壳操作指南                              |
| `launch_x64dbg.bat`  | 一键启动调试器                               |
| `x64dbg/`            | x64dbg 调试器                            |
| `ScyllaHide/`        | 反反调试插件（已配置 Themida profile）           |
| `radare2-6.1.4-w64/` | 静态分析框架                                |
| `.venv-unlicense/`   | Python 虚拟环境（unlicense/pyscylla/frida） |

---

# 七、附录

## 7.1 SHA256

```
b34da36f537dfce14551e1083c5f19ce7e33d8235034ef03cd549de4a9107594
```

## 7.2 分析基线

- 已确认：2620 个函数（`.text` 完整反汇编）、6061 条字符串、25+ 源文件
- 已深入分析：
  - **宿主桥接层**：modengine_ext_init 调用链 + vtable 布局
  - **联机会话中轴**：5 个关键函数（registry / 归约器 / 裁决器 / selector / 分类器）+ 全局数据结构
  - **语音聊天**：命令控制器（fcn.1800a47a0，10 BB）+ CSVoiceChatManager（fcn.1800b0400，558 BB）+ vtable 接口布局
  - **反作弊蜘蛛**：WhatIsPatchBytes + 镜像验证 + 断言策略
  - **网络适配层**：核心网络函数（fcn.1800202e0，10 callers）+ SoloParamRepository 系统
  - **YKNX3 协议**：17 个操作码分类
- 尚未深入：menu_man、lua_event_man、lock_tgt_man、world_chr_man、map_item_man、event_flag_man、fe_man、game_data_man、emk_system
- 仍未解密：Themida 壳区（71% 文件体积），含大厅状态机和网络加密参数
