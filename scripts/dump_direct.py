"""Load ersc.dll and dump it from the same process."""
import ctypes, os, sys

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

# Call modengine_ext_init to trigger full unpacking
try:
    init_addr = kernel32.GetProcAddress(h, b'modengine_ext_init')
    if init_addr:
        print(f"modengine_ext_init at: 0x{init_addr:X}")
        # Call it with NULL arg
        init_func = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(init_addr)
        print("Calling modengine_ext_init(NULL)...")
        init_func(None)
        print("modengine_ext_init returned")
except Exception as e:
    print(f"Error calling init: {e}")

# Now dump using pyscylla
pid = os.getpid()
print(f"Dumping from PID {pid}, base 0x{h:X}...")

import pyscylla

# Use the PE header entry point (0x30b380) since that's what's in the original PE
# pyscylla will fix things up
entry_point = h + 0x30b380  # Original entry point RVA

try:
    pyscylla.dump_pe(pid, h, entry_point, "ersc_dumped.exe", None)
    print("Dump successful: ersc_dumped.exe")
except Exception as e:
    print(f"Dump failed: {e}")
    # Try with entry_point = h (base address as entry point)
    try:
        pyscylla.dump_pe(pid, h, h, "ersc_dumped2.exe", None)
        print("Dump successful (alt): ersc_dumped2.exe")
    except Exception as e2:
        print(f"Alt dump also failed: {e2}")

