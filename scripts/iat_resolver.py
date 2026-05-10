"""
iat_resolver.py - Parse DLL export tables to match addresses to function names.
"""
import ctypes
import struct
import os

os.chdir(r'C:\Users\gkd2323c\Documents\Hanako\dll')

# Load ersc.dll first
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.LoadLibraryExW.restype = ctypes.c_void_p
h = kernel32.LoadLibraryExW('ersc.dll', None, 0x8)
print(f"ersc.dll @ 0x{h:X}")

# Get list of loaded modules
psapi = ctypes.WinDLL('psapi')
psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
psapi.EnumProcessModules.restype = ctypes.c_bool
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
psapi.GetModuleBaseNameW.restype = ctypes.c_ulong
psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
psapi.GetModuleInformation.restype = ctypes.c_bool

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_ulong),
        ("EntryPoint", ctypes.c_void_p),
    ]

# Enumerate modules
hProcess = ctypes.c_void_p(-1)  # current process
modules = (ctypes.c_void_p * 1024)()
cb_needed = ctypes.c_ulong(0)
psapi.EnumProcessModules(hProcess, modules, ctypes.sizeof(modules), ctypes.byref(cb_needed))

print(f"\nParsing export tables for {cb_needed.value // 8} modules...")

# Build export lookup: (dll_base, dll_name) -> {rva: func_name}
export_db = {}

for i in range(cb_needed.value // 8):
    mod_handle = modules[i]
    if not mod_handle:
        continue
    
    # Get module name
    name_buf = ctypes.create_unicode_buffer(260)
    psapi.GetModuleBaseNameW(hProcess, mod_handle, name_buf, 260)
    mod_name = name_buf.value
    
    # Get module info
    info = MODULEINFO()
    psapi.GetModuleInformation(hProcess, mod_handle, ctypes.byref(info), ctypes.sizeof(info))
    mod_base = info.lpBaseOfDll
    
    # Parse export table from PE header in memory
    try:
        # Read DOS header
        dos = ctypes.c_ubyte.from_address(mod_base)
        # PE signature
        pe_offset = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(mod_base + 0x3C), 0)[0]
        pe_sig = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(mod_base + pe_offset), 0)[0]
        if pe_sig != 0x4550:  # 'PE\0\0'
            continue
        
        # Optional header
        opt_hdr_off = mod_base + pe_offset + 4 + 20  # Skip COFF header
        magic = struct.unpack_from('<H', (ctypes.c_ubyte * 2).from_address(opt_hdr_off), 0)[0]
        if magic == 0x20B:  # PE32+
            export_rva = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(opt_hdr_off + 112), 0)[0]
        else:  # PE32
            export_rva = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(opt_hdr_off + 96), 0)[0]
        
        if export_rva == 0:
            continue
        
        # Read export directory
        exp_base = mod_base + export_rva
        exp_data = (ctypes.c_ubyte * 40).from_address(exp_base)
        
        num_names = struct.unpack_from('<I', exp_data, 24)[0]
        funcs_rva = struct.unpack_from('<I', exp_data, 28)[0]
        names_rva = struct.unpack_from('<I', exp_data, 32)[0]
        ordinals_rva = struct.unpack_from('<I', exp_data, 36)[0]
        
        if num_names == 0 or num_names > 10000:
            continue
        
        funcs_addr = mod_base + funcs_rva
        names_addr = mod_base + names_rva
        ords_addr = mod_base + ordinals_rva
        
        exports = {}
        for j in range(num_names):
            name_rva = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(names_addr + j * 4), 0)[0]
            ordinal = struct.unpack_from('<H', (ctypes.c_ubyte * 2).from_address(ords_addr + j * 2), 0)[0]
            func_rva = struct.unpack_from('<I', (ctypes.c_ubyte * 4).from_address(funcs_addr + ordinal * 4), 0)[0]
            
            # Read name
            name_bytes = (ctypes.c_ubyte * 256).from_address(mod_base + name_rva)
            try:
                func_name = ctypes.string_at(mod_base + name_rva).decode('utf-8', errors='ignore')
            except:
                func_name = f"#{ordinal}"
            
            exports[func_rva] = func_name
        
        export_db[id(mod_handle)] = (mod_name, mod_base, exports)
    
    except Exception as e:
        pass

print(f"Parsed exports for {len(export_db)} modules")

# Now match the IAT targets from our previous scan
# I'll just look up the external entries we found

# Key addresses to resolve (from the first run's output):
targets_to_resolve = {
    'KERNEL32.DLL': [0x1BC60, 0x23B90, 0x1AA50, 0x5E90, 0x1F9C0, 0x1B100, 0x1C080, 0x23B20, 0x1C040, 0x15CA0, 0x1D020, 0x20CE0, 0x16210, 0x1D0D0, 0x15C60],
    'WS2_32.dll': [0x13780, 0x13720, 0x58E0, 0x12620, 0x5630, 0x2890, 0x22F0, 0x12B80, 0x5730, 0x12EF0, 0x7E40, 0x12370, 0x137A0, 0x11A60, 0x12880, 0x12A90, 0x11D90, 0x11140, 0x14450, 0x12280, 0xD100, 0x13A80, 0x29160, 0x12CB0, 0x11C50, 0x120D0],
    'ntdll.dll': [0x200A0, 0x17480, 0xAA80, 0x1BDB0, 0x11D80, 0x69240],
    'steam_api64.dll': [0x7540],
    'WLDAP32.dll': [0x441E0, 0x1BD20, 0x22010, 0x44140, 0x121C0, 0x38B30, 0xEF30, 0x39310, 0x38440, 0x38820, 0x27FD0, 0x44240, 0xF0F0, 0x393F0, 0x3A090, 0x12400, 0x28070, 0x42370],
    'ADVAPI32.dll': [0x15660],
}

print("\n" + "=" * 70)
print("RESOLVED IMPORT TABLE")
print("=" * 70)

for mod_name, rvas in targets_to_resolve.items():
    print(f"\n--- {mod_name} ---")
    
    # Find this module in our export_db
    mod_exports = None
    mod_base = 0
    for key, (name, base, exports) in export_db.items():
        if name.lower() == mod_name.lower():
            mod_exports = exports
            mod_base = base
            break
    
    if not mod_exports:
        print("  (module not found in export DB)")
        continue
    
    for rva in rvas:
        # Find the nearest export that's at or before this RVA
        best_rva = 0
        best_name = f"+0x{rva:X}"
        for exp_rva, exp_name in sorted(mod_exports.items()):
            if exp_rva <= rva:
                best_rva = exp_rva
                best_name = exp_name
        
        if best_rva == rva:
            print(f"  +0x{rva:05X} → {best_name}")
        else:
            offset = rva - best_rva
            print(f"  +0x{rva:05X} → {best_name}+0x{offset:X}")

print(f"\n{'=' * 70}")
print("Note: +offset after function name means it's a wrapper/thunk")
print("or forwarded export within the DLL.")
