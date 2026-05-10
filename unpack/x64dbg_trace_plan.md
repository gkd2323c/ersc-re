# x64dbg 动态追踪方案 v2

> 更新日期：2026-05-10
> 关键发现：Mod Engine 2 内置 ScyllaHide，可用硬件断点绕过 Theida+Arxan 双重检测

---

## 一、推荐方案：Mod Engine 2 + ScyllaHide + x64dbg 硬件断点

### 1.1 为什么这个方案可行

之前 Frida 闪退是因为 **两层保护同时起作用**：

| 保护层 | 检测对象 | 检测方式 |
|--------|---------|---------|
| Themida 3.x | ersc.dll 自身 | Frida 检测 + 内存 patch 检测 |
| Arxan (GuardIT) | eldenring.exe 代码 | 定时器代码完整性校验 |

**破解思路**：
1. **ScyllaHide**（Mod Engine 2 内置）→ 绕过 Arxan 的反调试
2. **硬件断点**（DR0-DR3）→ 不写代码，不被完整性校验检测到
3. **只在 ersc.dll 函数上设断点** → Themida 已经解壳了这些区域，且不在 Arxan 保护范围内

### 1.2 操作步骤

**第一步：启用 ScyllaHide**

在 Mod Engine 2 的 `config_eldenring.toml` 最底部添加：

```toml
[extension.scylla_hide]
enabled = true
```

**第二步：启动游戏**

通过 Mod Engine 2 的 `launchmod_eldenring.bat` 启动 Elden Ring。

**第三步：Attach x64dbg**

```
1. 打开 x64dbg
2. File → Attach → 选择 eldenring.exe
3. 游戏会暂停。在 Symbols 面板找到 ersc.dll
```

**第四步：设硬件断点**

x64dbg 的硬件断点（不修改代码，Arxan 检测不到）。在命令栏输入：

```
// 硬件执行断点（最多 4 个）
SetHardwareBreakpoint ersc.dll + 0x26eb0   // Session Registry
SetHardwareBreakpoint ersc.dll + 0x8b4c0   // Join Byte Decide
SetHardwareBreakpoint ersc.dll + 0x202e0   // NetCore
SetHardwareBreakpoint ersc.dll + 0xa47a0   // VoiceChat
```

> 硬件断点限制：最多 4 个同时激活。用 `bdh` / `beh` 来开关。

**第五步：运行观察**

按 F9 运行游戏。进入联机区域，触发建房/搜房/加入流程。

断点命中时记录：
- 寄存器面板（rcx, rdx, r8, r9）
- 调用栈（Call Stack 面板）
- 按 F9 继续

---

## 二、备用方案

### 方案 A：软件断点 + ScyllaHide（风险）

如果硬件断点 4 个不够用，可以尝试软件断点（`bp` 命令）。但**只在 ersc.dll 内部函数上使用**，不要在 `eldenring.exe` 本身的代码上设软件断点。

```
bp ersc.dll + 0x26eb0
bp ersc.dll + 0x8032a
```

### 方案 B：dearxan 彻底禁用

如果 ScyllaHide 不够（例如 Elden Ring Nightreign 增加了新的 Arxan 反制），可以改用 [dearxan](https://crates.io/crates/dearxan)：

```
dearxan --game "ELDEN RING" --game-dir "C:\Program Files\Steam\steamapps\common\ELDEN RING\Game"
```

这会彻底禁用所有 Arxan stub，然后可以自由使用任何调试工具。

---

## 三、断点优先级

| 顺序 | 地址 | 函数 | 触发条件 | 预期数据 |
|------|------|------|---------|---------|
| 1 | `ersc.dll + 0x26eb0` | Session Registry | 建房/搜房操作 | OnBeJoinType 值、session 指针 |
| 2 | `ersc.dll + 0x8b4c0` | Join Byte Decide | 每次连接判定 | rdx 目标对象、返回值枚举 |
| 3 | `ersc.dll + 0x202e0` | NetCore | 网络事件 | rdx 事件码（0x803/0x804/0x7ee 等） |
| 4 | `ersc.dll + 0xa47a0` | VoiceChat | 语音开关 | rcx this 指针 |

---

## 四、参考文献

- [Reversing Arxan (GuardIT)](https://me3.help/en/latest/blog/posts/arxan-reversing-1/) — Arxan stub 结构、定时器校验模式
- [dearxan crate](https://crates.io/crates/dearxan) — 彻底的 Arxan 禁用工具
- [ModEngine2](https://github.com/soulsmods/ModEngine2) — ScyllaHide 集成
