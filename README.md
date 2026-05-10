# Elden Ring Seamless Co-op (ersc.dll) Reverse Engineering

Elden Ring 无缝联机 Mod v1.9.9 的 DLL 逆向工程分析。

**目标文件**：`ersc.dll`（7.8 MB，Themida 3.x 加壳）  
**作者**：Yui（[Seamless Co-op Mod](https://www.nexusmods.com/eldenring/mods/510)）  
**分析日期**：2026-05-08 ~ 2026-05-10  
**工具**：radare2 6.1.4 + Python + x64dbg + Frida

---

## 文件结构

```
ersc-re/
├── analysis/
│   ├── ersc_analysis.md      # 主分析报告（结构化的完整文档）
│   ├── ersc_strings.txt      # 6061 条提取的字符串
│   └── ersc_functions.txt    # 2620 个函数列表
├── scripts/
│   ├── iat_rebuilder.py      # IAT 扫描 + DLL 导出表解析
│   ├── iat_resolver.py       # 运行时 API 名称解析
│   ├── auto_trace.py         # Frida 全自动追踪（未成功）
│   ├── ersc_tracer.js        # Frida 追踪脚本（13 hooks 版）
│   ├── ersc_tracer_lite.js   # Frida 追踪脚本（轻量版）
│   ├── ersc_tracer_runner.py # Frida 追踪 Python 运行器
│   ├── dump_direct.py        # ctypes 加载 + pyscylla 内存 dump
│   ├── dump_ersc.py          # ctypes 加载 + 信号等待外部 dump
│   ├── trace_themida.py      # Frida 监控 DLL 加载过程
│   └── loader.c              # C 语言 DLL 加载器
└── unpack/
    ├── unpack_guide.md       # Themida 手工脱壳指南
    ├── x64dbg_trace_plan.md  # x64dbg 动态追踪方案
    ├── unpack_ersc.txt       # x64dbg 自动脱壳脚本
    └── launch_x64dbg.bat     # 一键启动器
```

## 分析内容覆盖

- [x] 文件身份、节段布局、保护机制识别
- [x] `modengine_ext_init` 完整调用链 + vtable 布局
- [x] 五层架构模型（桥接层 → CS 管理器 → 网络 → 功能模块 → 壳区）
- [x] 联机会话中轴（session registry / 状态归约 / join 裁决）
- [x] 语音聊天模块（命令控制器 + CSVoiceChatManager）
- [x] 反作弊蜘蛛（CSCheatDetectionSpider）
- [x] 网络适配层 + SoloParamRepository
- [x] YuiKeyNexus3 协议操作码（17 个）
- [x] CS 子模块引用密度分析（9 个模块）
- [x] 完整导入表重建（67 个 API，含隐藏的 WLDAP32/LDAP 依赖）
- [x] Frida 动态追踪运行时验证
- [ ] `.themida` 壳区（5.5 MB，71%，含大厅状态机 + 加密参数）

## 免责声明

本项目仅用于安全研究和教育目的。`ersc.dll` 的版权归原作者 Yui 所有。本仓库不包含 `ersc.dll` 原始文件或其脱壳产物。

## 许可证

MIT
