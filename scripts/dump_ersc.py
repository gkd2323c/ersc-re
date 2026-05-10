"""Load ersc.dll and dump it from memory using pyscylla."""
import ctypes, os, sys, time

os.chdir(r"C:\Users\gkd2323c\Documents\Hanako\dll")

# Load kernel32
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.LoadLibraryExW.restype = ctypes.c_void_p

LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
h = kernel32.LoadLibraryExW('ersc.dll', None, LOAD_WITH_ALTERED_SEARCH_PATH)

if not h:
    print(f"LoadLibrary failed: {ctypes.get_last_error()}")
    sys.exit(1)

print(f"DLL loaded at: 0x{h:X}")

# Get PID
pid = os.getpid()
print(f"PID: {pid}")

# Wait for Frida to attach (we'll signal via file)
signal_file = "dump_signal.txt"
with open(signal_file, 'w') as f:
    f.write(f"PID={pid}\nBASE={h:X}\n")

print(f"Signal written to {signal_file}")
print("Waiting for dump to complete (60s)...")
time.sleep(60)
print("Done waiting")
