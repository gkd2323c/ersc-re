/**
 * ersc_tracer.js
 * 在 Elden Ring + Seamless Co-op 实机运行环境中追踪 ersc.dll 关键函数
 *
 * 使用方式:
 *   1. 启动 Elden Ring (已安装 Seamless Co-op Mod)
 *   2. 进入游戏后，在联机区域触发联机流程
 *   3. 运行: python ersc_tracer_runner.py
 */

var base = null;
var hooked = [];
var logBuffer = [];

function log(msg) {
    var line = '[' + new Date().toISOString() + '] ' + msg;
    console.log(line);
    logBuffer.push(line);
    if (logBuffer.length > 1000) logBuffer.shift();
}

// Wait for ersc.dll to load
function findErsc() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.toLowerCase().indexOf('ersc') >= 0) {
            base = mods[i].base;
            log('Found ersc.dll at ' + base + ' (size: ' + mods[i].size + ')');
            return true;
        }
    }
    return false;
}

function installHooks() {
    var targets = [
        // === 联机会话 ===
        { name: 'SessionRegistry',    off: 0x26eb0, desc: '会话注册表查找入口' },
        { name: 'GameMan_SessCall',   off: 0x8032a, desc: 'game_man 侧 session 调用' },
        { name: 'Join_Classifier',    off: 0x27020, desc: 'Join type 分类器 (0-3)' },
        { name: 'ObjSelector',        off: 0x24bc0, desc: '活动对象选择器' },
        
        // === Join/Be-Join 裁决 ===
        { name: 'Join_ByteDecide',    off: 0x8b4c0, desc: '字节级 join 裁决器' },
        { name: 'Join_BoolDecide',    off: 0x8b7e0, desc: 'join 布尔判定器' },
        { name: 'Join_PostApply',     off: 0x8b960, desc: 'join 后处理/应用' },
        
        // === 语音 ===
        { name: 'VoiceChat_Ctrl',     off: 0xa47a0, desc: '语音命令控制器' },
        
        // === 初始化/游戏逻辑 ===
        { name: 'Init_Orch',          off: 0x3cc30, desc: '初始化编排器' },
        { name: 'GameLogic_Main',     off: 0x96960, desc: '游戏逻辑主循环' },
        { name: 'GameLogic_Large',    off: 0x9d450, desc: '大面积游戏逻辑' },
        
        // === 网络 ===
        { name: 'Networking_Core',    off: 0x202e0, desc: '核心网络函数' },
        
        // === 反作弊 ===
        { name: 'ParamRepo',          off: 0xa6f10, desc: 'SoloParamRepository 读取' },
    ];

    for (var i = 0; i < targets.length; i++) {
        var t = targets[i];
        var addr = base.add(t.off);
        
        try {
            (function(target) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        log('>>> [' + target.name + '] ' + target.desc);
                        log('      rcx=' + this.context.rcx + ' rdx=' + this.context.rdx +
                            ' r8=' + this.context.r8 + ' r9=' + this.context.r9);
                    },
                    onLeave: function(retval) {
                        log('  [' + target.name + '] => ' + retval);
                    }
                });
            })(t);
            hooked.push(t.name);
        } catch(e) {
            log('FAILED to hook ' + t.name + ': ' + e);
        }
    }
    
    log('Installed ' + hooked.length + '/' + targets.length + ' hooks');
}

// Try to find DLL immediately (might already be loaded)
if (findErsc()) {
    installHooks();
} else {
    // Hook LoadLibrary to catch ersc.dll loading
    log('ersc.dll not loaded yet, waiting for LoadLibrary...');
    Interceptor.attach(Module.findExportByName(null, 'LoadLibraryExW'), {
        onEnter: function(args) {
            this.path = args[0].readUtf16String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.toLowerCase().indexOf('ersc') >= 0 && retval.toInt32() !== 0) {
                base = retval;
                log('ersc.dll loaded at ' + base);
                installHooks();
            }
        }
    });
}

// Send ready signal
send({type: 'ready', hooks: hooked});

// Periodically flush log
setInterval(function() {
    if (logBuffer.length > 0) {
        send({type: 'log', entries: logBuffer.splice(0)});
    }
}, 2000);
