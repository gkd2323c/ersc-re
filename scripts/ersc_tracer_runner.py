"""
ersc_tracer_runner.py
Attach to Elden Ring process, inject ersc_tracer.js, log output to file.

Usage: python ersc_tracer_runner.py
"""
import frida
import sys
import json
import os
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "ersc_trace_log.txt")
TRACER_JS = os.path.join(SCRIPT_DIR, "ersc_tracer_lite.js")

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'log':
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                for entry in payload['entries']:
                    f.write(entry + '\n')
                    print(entry)
        elif payload.get('t') == 'L':
            # Lite tracer format
            line = payload['m']
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
            print(line)
        elif payload.get('type') == 'ready' or payload.get('type') == 'waiting':
            if payload.get('type') == 'ready':
                print(f"[*] Tracer ready. Hooks installed.")
            print(f"[*] Logging to: {LOG_FILE}")
            print("[*] Now play the game. Trigger co-op features.")
            print("[*] Press Ctrl+C to stop.\n")
        else:
            print(f"[Frida] {payload}")
    elif message['type'] == 'error':
        print(f"[Error] {message}")
    else:
        print(f"[Frida] {message}")

def main():
    print("=" * 60)
    print(" ersc.dll Dynamic Tracer")
    print("=" * 60)
    
    # Find eldenring.exe
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    
    target = None
    for p in processes:
        if p.name.lower() == 'eldenring.exe':
            target = p
            break
    
    if not target:
        print("[!] eldenring.exe not found. Start the game first.")
        print("    (Make sure Seamless Co-op mod is installed)")
        sys.exit(1)
    
    print(f"[*] Found: {target.name} (PID {target.pid})")
    print(f"[*] Attaching...")
    
    session = device.attach(target.pid)
    
    # Load tracer script
    with open(TRACER_JS, 'r', encoding='utf-8') as f:
        script_code = f.read()
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print(f"[*] Attached. Log starting at {datetime.now().isoformat()}")
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n=== Session started: {datetime.now().isoformat()} ===\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()
        print(f"[*] Log saved to: {LOG_FILE}")

if __name__ == '__main__':
    main()
