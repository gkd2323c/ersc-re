"""
ersc.dll auto-tracer
使用 Python ctypes 加载 DLL（触发 Themida 解壳），
然后用 Frida 在已解密的 .text 函数上设 hook，
最后调用 modengine_ext_init 触发执行。
"""
import ctypes
import os
import sys
import time

os.chdir(r"C:\Users\gkd2323c\Documents\Hanako\dll")

# ============================================================
# Step 1: Load DLL via ctypes (triggers Themida decryption)
# ============================================================
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.LoadLibraryExW.restype = ctypes.c_void_p

LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
h = kernel32.LoadLibraryExW('ersc.dll', None, LOAD_WITH_ALTERED_SEARCH_PATH)

if not h:
    err = ctypes.get_last_error()
    print(f"[FATAL] LoadLibrary failed: {err}")
    sys.exit(1)

print(f"[OK] ersc.dll loaded at 0x{h:X}")

# ============================================================
# Step 2: Define key hook points
# ============================================================
HOOKS = {
    "modengine_ext_init": h + 0x2b00,
    "SessionRegistry":   h + 0x26eb0,
    "GameMan_Session":   h + 0x8032a,
    "VoiceChat_Ctrl":    h + 0xa47a0,
    "Init_Orchestrator": h + 0x3cc30,
}

print("\n[Hook Targets]")
for name, addr in HOOKS.items():
    print(f"  {name}: 0x{addr:X} (offset +0x{addr - h:X})")

# ============================================================
# Step 3: Attach Frida to self and install hooks
# ============================================================
import frida

pid = os.getpid()
print(f"\n[Frida] Attaching to self (PID {pid})...")

session = frida.attach(pid)

hook_script = """
// recv from Python
recv('config', function(cfg) {
    console.log('[Frida] Installing ' + Object.keys(cfg.hooks).length + ' hooks...');
    
    for (var name in cfg.hooks) {
        var addr = ptr(cfg.hooks[name]);
        console.log('[Frida] Hooking ' + name + ' at ' + addr);
        
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log('\\n=== [' + name + '] ENTER ===');
                console.log('  rcx = ' + this.context.rcx);
                console.log('  rdx = ' + this.context.rdx);
                console.log('  r8  = ' + this.context.r8);
                console.log('  r9  = ' + this.context.r9);
                
                // Log first few qwords at rcx
                try {
                    var base = this.context.rcx;
                    console.log('  [rcx+0x00] = ' + base.readPointer());
                    console.log('  [rcx+0x08] = ' + base.add(0x08).readPointer());
                    console.log('  [rcx+0x10] = ' + base.add(0x10).readPointer());
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('  => ret = ' + retval);
            }
        });
    }
    
    console.log('[Frida] All hooks installed. Sending ready signal...');
    send({type: 'ready'});
});
"""

script = session.create_script(hook_script)

results = []
def on_message(message, data):
    if message['type'] == 'send':
        results.append(message['payload'])
    elif message['type'] == 'error':
        print(f"[Frida Error] {message}")
    else:
        print(f"[Frida] {message['payload']}" if 'payload' in message else f"[Frida] {message}")

script.on('message', on_message)
script.load()

# Send hook configuration
import json
script.post({'type': 'config', 'hooks': {k: f"{v}" for k, v in HOOKS.items()}})

# Wait for ready signal
time.sleep(2)

# ============================================================
# Step 4: Call modengine_ext_init to trigger the init chain
# ============================================================
print("\n[Action] Calling modengine_ext_init(NULL)...")
print("=" * 50)

try:
    init_addr = h + 0x2b00
    init_func = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)(init_addr)
    ret = init_func(None)
    print(f"\n[Result] modengine_ext_init returned: {ret}")
except Exception as e:
    print(f"\n[Error] modengine_ext_init call failed: {e}")

# Wait for any pending Frida messages
time.sleep(2)

print("\n" + "=" * 50)
hook_count = len([r for r in results if r.get('type') == 'ready'])
print(f"[Done] Hooks triggered: {len(results)} events")
session.detach()
