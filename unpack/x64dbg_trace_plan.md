# x64dbg 动态追踪方案

> 目标：在关键函数设断点，触发游戏联机流程，获取运行时数据
> 前置：x64dbg + ScyllaHide（Themida profile）已配置

---

## 一、加载方案

### 方案 A：用 loaddll.exe 直接加载

```
1. 打开 x64dbg/release/x64/x64dbg.exe
2. File > Open → x64dbg/release/x64/loaddll.exe
3. Arguments: C:\Users\gkd2323c\Documents\Hanako\dll\ersc.dll
4. Working Directory: C:\Users\gkd2323c\Documents\Hanako\dll
5. 确认 ScyllaHide 已启用 Themida profile
```

> 此方案只能测试 DLL 加载和 DllMain 执行。modengine_ext_init 需要 Mod Engine 传入宿主接口，loaddll 不会触发完整初始化。

### 方案 B：挂载到 Elden Ring 进程（推荐）

```
1. 启动 Elden Ring（已安装 Seamless Co-op Mod）
2. x64dbg → File → Attach → 选择 eldenring.exe
3. 在 Symbols 面板找到 ersc.dll 模块
4. 确认 DLL 已被加载后设断点
```

> 此方案能捕获真实游戏进程中 DLL 的所有运行时行为。

### 方案 C：用 loader.c 编译加载

```
1. 编译 loader.c: gcc -o loader.exe loader.c
2. x64dbg → File → Open → loader.exe
3. loader.exe 会调用 LoadLibrary + modengine_ext_init(NULL)
```

> modengine_ext_init(NULL) 可能因缺少有效宿主接口而走异常路径，但可触发部分初始化链。

---

## 二、断点设置

### 优先级 1：联机会话中轴

| 地址 | 函数/标记 | 目的 |
|------|----------|------|
| `ersc.dll + 0x26eb0` | fcn.180026eb0 | session registry 入口，观察 OnBeJoinType 诊断 |
| `ersc.dll + 0x26e6d` | OnBeJoinType 字符串引用点 | 捕获 join type 日志输出 |
| `ersc.dll + 0x8032a` | game_man 侧的 session 调用 | 观察 session 查找请求来源 |

### 优先级 2：语音聊天

| 地址 | 函数/标记 | 目的 |
|------|----------|------|
| `ersc.dll + 0xa47a0` | fcn.1800a47a0 | Play/Stop VoiceChat 命令入口 |
| `ersc.dll + 0xa4963` | "Stop_VoiceChat" 字符串处 | 捕获停止语音命令 |
| `ersc.dll + 0xa49b5` | "Play_VoiceChat" 字符串处 | 捕获开始语音命令 |

### 优先级 3：初始化链

| 地址 | 函数/标记 | 目的 |
|------|----------|------|
| `ersc.dll + 0x3cc30` | fcn.18003cc30 | 最大初始化编排器（512 BB） |
| `ersc.dll + 0x96960` | fcn.180096960 | 游戏逻辑主循环（426 BB） |
| `ersc.dll + 0x9d450` | fcn.18009d450 | 大面积游戏逻辑（476 BB） |

### 优先级 4：导出入口

| 地址 | 函数/标记 | 目的 |
|------|----------|------|
| `ersc.dll + 0x2b00` | modengine_ext_init | 导出入口，观察调用参数和返回 |
| `ersc.dll + 0x28a30` | jmp to .themida | 观察是否真的跳入壳区 |

---

## 三、x64dbg 脚本

```
// =========================================
// ersc.dll 动态追踪脚本
// =========================================

// 清除旧断点
bpc
bphc
bpmc

log "========================================"
log "ersc.dll Dynamic Trace Script"
log "========================================"
log "Setting breakpoints..."

// ---- 优先级 1：联机会话 ----
bp ersc.dll + 0x26eb0
bp ersc.dll + 0x8032a

// ---- 优先级 2：语音聊天 ----
bp ersc.dll + 0xa47a0

// ---- 优先级 3：初始化 ----
bp ersc.dll + 0x3cc30
bp ersc.dll + 0x96960
bp ersc.dll + 0x9d450

// ---- 优先级 4：导出入口 ----
bp ersc.dll + 0x2b00

// 设置日志
bpcnd ersc.dll + 0x26eb0, "log \"[Session Registry] called, rcx={rcx}, rdx={rdx}, r8={r8}\""
bpcnd ersc.dll + 0x2b00, "log \"[modengine_ext_init] called, rcx={rcx}\""
bpcnd ersc.dll + 0xa47a0, "log \"[VoiceChat Controller] called, rcx={rcx}\""
bpcnd ersc.dll + 0x3cc30, "log \"[Init Orchestrator] called, rcx={rcx}\""

log "Breakpoints set. Run the program."
log "========================================"
```

---

## 四、预期可获取的信息

### 从 session registry (0x26eb0)：
- `OnBeJoinType (%u)` 的实际参数值 → 验证 join type 枚举（0/1/2/3）
- `rcx` 参数指向的全局对象 → 确认 session registry 表的基地址
- `rdx` 参数（arg2+0x218 比较对象）→ 理解连接对象的布局
- 返回值（rax）→ 确认哪些路径能命中 session

### 从 voice chat (0xa47a0)：
- 何时触发 Play/Stop → 理解语音激活的触发条件
- `r13` 指向的状态对象 → dump `+0xb68` 观察活跃标志变化
- vtable 调用链的运行时参数

### 从初始化 (0x3cc30)：
- 调用顺序 → 确认管理器的初始化先后关系
- `rcx` 参数 → 确认初始化器的 this 对象

---

## 五、注意事项

1. **ScyllaHide 必须开启 Themida profile**，否则 x64dbg 会被 Themida 检测并 crash
2. **方案 B（挂载游戏进程）最真实但最复杂**：游戏反作弊可能干扰，且 DLL 加载时间窗口短
3. **方案 A（loaddll）最简单但最不完整**：modengine_ext_init 不会被调用
4. **先试方案 A**，确认 DLL 能加载且 ScyllaHide 生效，再尝试方案 B
5. 断点触发后，用 `d rcx`（dump rcx 指向内存）和 `? rcx - ersc.dll`（计算偏移）获取结构化数据
