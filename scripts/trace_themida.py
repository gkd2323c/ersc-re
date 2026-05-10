"""Quick Frida trace: see what happens when ersc.dll loads."""
import frida
import sys
import time

def on_message(message, data):
    print(f"[{message['type']}] {message.get('payload', message)}")

dll_path = r"C:\Users\gkd2323c\Documents\Hanako\dll\ersc.dll"

# Spawn rundll32 suspended
pid = frida.spawn([r"C:\Windows\System32\rundll32.exe", dll_path, "#0"])
print(f"Spawned PID: {pid}")

session = frida.attach(pid)

script_code = """
// Hook LdrLoadDll to see when our DLL loads
const LdrLoadDll = Module.findExportByName('ntdll', 'LdrLoadDll');
Interceptor.attach(LdrLoadDll, {
    onEnter(args) {
        const path = args[0].readUtf16String();
        if (path && path.toLowerCase().includes('ersc')) {
            console.log('[LdrLoadDll] Loading: ' + path);
        }
    },
    onLeave(retval) {
    }
});

// Monitor exceptions
Process.setExceptionHandler(ex => {
    console.log('[Exception] type=' + ex.type + ' addr=' + ex.context.pc + ' memory=' + JSON.stringify(ex.memory));
    return false;
});

console.log('Script loaded, resuming process...');
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

frida.resume(pid)

# Wait a few seconds
time.sleep(5)

# Check if process is still alive
try:
    proc = frida.get_local_device().get_process(pid)
    print(f"Process still alive: {proc.name}")
except Exception as e:
    print(f"Process terminated: {e}")

session.detach()
