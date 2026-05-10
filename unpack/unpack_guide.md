# ersc.dll 手动脱壳指南

> 目标：Themida 3.x 加壳的 Elden Ring Seamless Co-op DLL
> 工具：x64dbg + ScyllaHide

---

## 准备工作

1. 确认 `steam_api64.dll` 与 `ersc.dll` 在同一目录
2. 确认 ScyllaHide 插件已复制到 x64dbg 的 `plugins\` 目录：
   ```
   x64dbg/release/x64/plugins/
   ├── ScyllaHideX64DBGPlugin.dp64
   ├── HookLibraryx64.dll
   └── scylla_hide.ini
   ```

---

## 步骤一：配置 ScyllaHide

1. 打开 `x64dbg/release/x64/x64dbg.exe`
2. 菜单：**Plugins > ScyllaHide**
3. 勾选 **x64dbg** 选项卡
4. Profile 选择 **Themida**
5. 确认以下选项已开启：
   - PEB->BeingDebugged
   - NtQueryInformationProcess
   - NtQuerySystemInformation
   - NtSetInformationThread
   - NtClose (anti-anti-attach)
   - GetTickCount / QueryPerformanceCounter

---

## 步骤二：加载 DLL 宿主进程

ersc.dll 是 DLL，需要宿主进程来加载。推荐两种方式：

### 方式 A：使用 x64dbg 内置 DLL 加载器（推荐）

1. **File > Open**，选择 `x64dbg/release/x64/loaddll.exe`
2. 在 **Arguments** 输入框中填入 ersc.dll 的完整路径：
   ```
   C:\Users\gkd2323c\Documents\Hanako\dll\ersc.dll
   ```
3. **Working Directory** 设为 DLL 所在目录
4. 点击 **Open**

x64dbg 会以暂停状态启动宿主进程，停在系统断点。

### 方式 B：使用 rundll32

1. **File > Open**，选择 `C:\Windows\System32\rundll32.exe`
2. **Arguments**：
   ```
   "C:\Users\gkd2323c\Documents\Hanako\dll\ersc.dll",#0
   ```
3. 同上设置工作目录

---

## 步骤三：监控解壳过程

Themida 3.x 解壳时常见的 API 调用序列：

| 顺序 | API | 含义 |
|------|-----|------|
| 1 | `NtQueryInformationProcess` | Themida 检测调试器（应被 ScyllaHide 过滤） |
| 2 | `VirtualAlloc` | 分配解壳所需内存 |
| 3 | `VirtualProtect` | 修改代码段保护属性 |
| 4 | `NtProtectVirtualMemory` | 底层内存保护修改 |
| 5 | 代码跳转到真实入口 | OEP |

### 设置断点

在命令栏依次输入：
```
bp VirtualAlloc
bp VirtualProtect
bp NtProtectVirtualMemory
```

### 运行观察

1. 按 **F9** 运行
2. 如果 ScyllaHide 生效，程序不会检测到调试器
3. 逐个观察断点触发：
   - 第一次 `VirtualAlloc`：Themida 分配工作内存
   - `VirtualProtect`：开始修改代码段保护
   - 后续 `VirtualProtect`：逐步解密各段代码

---

## 步骤四：定位 OEP

### 方法一：脚本自动查找

1. 打开 **Script** 面板（View > Script）
2. 右键 **Load Script**，选择 `unpack_ersc.txt`
3. 按空格键执行脚本
4. 等待 OEP 标注出现在反汇编窗口

### 方法二：手动查找

1. 在 Memory 面板找到 `ersc.dll` 的 `.text` 段
2. 右键 `.text` 段 > **Follow in Disassembler**
3. 在代码区寻找被调用的函数（有 `call` 或 `jmp` 指向的地址）
4. 特征：Themida 3.x 的真实入口通常有堆栈帧设置：
   ```
   push rbp
   mov rbp, rsp
   sub rsp, ...
   ```

### 方法三：通过导出函数定位

由于 ersc.dll 已知导出 `modengine_ext_init`（RVA 0x2b00），可以在命令栏直接跳转：
```
d 180002b00
```
检查此处代码是否为真实代码（已解密）。

> 注意：`modengine_ext_init` 是 Mod Engine 的导出桥接层，不等同于 PE Header 中的原始入口点。最新反汇编表明，它会在运行时解析并保存 `AddressOfEntryPoint`（`0x18030b380`），再通过间接调用转交控制权。因此这里更适合用来观察接口包装、回调注册和入口转调链，而不是把它直接当作“最终 OEP”。

---

## 步骤五：Dump 和修复 IAT

1. 菜单：**Plugins > Scylla**
2. 在 Scylla 窗口中：
   - 从下拉列表选择 **ersc.dll** 模块
   - 点 **IAT Autosearch**（自动搜索导入表）
   - 点 **Get Imports**（获取导入函数）
   - 检查导入列表，确认没有无效项
   - 点 **Dump**，保存为 `ersc_unpacked.exe`
   - 点 **Fix Dump**，选择刚才的 dump 文件

---

## 步骤六：验证脱壳结果

脱壳后的文件应该：
1. 用 PE-bear 或 rabin2 检查，不再有 `.themida` 段
2. 导入表完整，包含 `steam_api64.dll` 等所有实际使用的 DLL
3. `.text` 段代码与脱壳前完全一致（已经可见）

验证命令：
```bash
rabin2 -I ersc_unpacked.exe
rabin2 -i ersc_unpacked.exe
rabin2 -s ersc_unpacked.exe
```

---

## 故障排查

| 问题 | 可能原因 | 解决 |
|------|----------|------|
| 程序在第一个断点前崩溃 | ScyllaHide 未生效 | 检查 Themida profile，重启 x64dbg |
| 断点从未触发 | 反调试检测成功 | 尝试「Run until user code」 |
| IAT Autosearch 找不到导入 | OEP 不正确 | 换一个候选 OEP 地址重试 |
| Dump 后文件无法加载 | 导入表修复不完整 | 手动修复缺失的导入项 |
| 错误 126 (模块未找到) | 运行 dump 时缺少依赖 | 将 steam_api64.dll 放在 dump 同目录 |

---

## 备选方案

如果 x64dbg 手动脱壳过于耗时，可以使用已获取的静态分析成果：
- `.text` 段 2620 个函数已可完整反汇编
- 6061 条字符串已提取
- `modengine_ext_init` 调用链已可追踪

对于大部分分析目标，直接分析 `.text` 段比完整脱壳更高效。
