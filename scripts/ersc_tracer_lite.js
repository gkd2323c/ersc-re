/**
 * ersc_tracer_lite.js - 轻量版，只 hook 核心函数
 */
var base = null;
var hitCount = {};
var logFile = null;

function qlog(msg) {
    // Minimal overhead logging
    send({t: 'L', m: msg});
}

function findAndHook() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.toLowerCase().indexOf('ersc') >= 0) {
            base = mods[i].base;
            break;
        }
    }
    if (!base) return false;
    qlog('ersc.dll @ ' + base);

    // Only 5 hooks, onEnter only, minimal work
    var hooks = [
        { name: 'SessionReg',  off: 0x26eb0 },
        { name: 'JoinDecide',  off: 0x8b4c0 },
        { name: 'VoiceChat',   off: 0xa47a0 },
        { name: 'NetCore',     off: 0x202e0 },
        { name: 'InitOrch',    off: 0x3cc30 },
    ];

    for (var i = 0; i < hooks.length; i++) {
        (function(h) {
            var addr = base.add(h.off);
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        // Only log first 5 hits of each to reduce noise
                        var c = hitCount[h.name] || 0;
                        hitCount[h.name] = c + 1;
                        if (c < 5 || c % 50 === 0) {
                            // Fast register dump
                            var s = h.name + ' #' + (c+1) + ' | rcx=' + this.context.rcx +
                                    ' rdx=' + this.context.rdx + ' r8=' + this.context.r8;
                            qlog(s);
                        }
                    }
                });
            } catch(e) {}
        })(hooks[i]);
    }

    qlog('Hooked: ' + Object.keys(hitCount).length + ' functions');
    return true;
}

// Try immediately
if (findAndHook()) {
    send({type: 'ready'});
} else {
    // Wait for LoadLibrary
    Interceptor.attach(Module.findExportByName(null, 'LoadLibraryExW'), {
        onEnter: function(args) {
            this.path = args[0].readUtf16String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.toLowerCase().indexOf('ersc') >= 0 && retval.toInt32()) {
                base = retval;
                findAndHook();
                send({type: 'ready'});
            }
        }
    });
    qlog('Waiting for ersc.dll...');
    send({type: 'waiting'});
}
