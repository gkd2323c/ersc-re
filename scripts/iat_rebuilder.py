"""
iat_rebuilder.py v2 - Use file-based reading + Safe memory probing
"""
import ctypes
import struct
import os

os.chdir(r'C:\Users\gkd2323c\Documents\Hanako\dll')

print("Loading DLL...")
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.LoadLibraryExW.restype = ctypes.c_void_p
h = kernel32.LoadLibraryExW('ersc.dll', None, 0x8)
if not h:
    print(f"LoadLibrary failed: {ctypes.get_last_error()}")
    exit(1)
print(f"ersc.dll @ 0x{h:X}")

# Read raw file for section data
with open('ersc.dll', 'rb') as f:
    raw = f.read()

def file_va_to_raw(va):
    """Convert VA to file offset considering section layout"""
    # .text:  file=0x400,   size=0x18c800, VA=0x180001000
    # .rdata: file=0x18d000, size=0x85400,  VA=0x18018d000
    base_va = 0x180000000
    if 0x180001000 <= va < 0x180001000 + 0x18c800:
        return 0x400 + (va - 0x180001000)
    elif 0x18018d000 <= va < 0x18018d000 + 0x85400:
        return 0x18d000 + (va - 0x18018d000)
    elif 0x180212400 <= va < 0x180212400 + 0x2000:  # .data
        return 0x18d000 + 0x85400 + (va - 0x180212400)
    return None

def file_read_bytes(va, n):
    off = file_va_to_raw(va)
    if off and off + n <= len(raw):
        return raw[off:off+n]
    return None

def mem_read_safe(va, n):
    """Safe memory read using kernel32"""
    buf = ctypes.create_string_buffer(n)
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        ctypes.c_void_p(-1),  # current process
        ctypes.c_void_p(va),
        buf, n,
        ctypes.byref(bytes_read)
    )
    if ok:
        return bytes(buf.raw[:bytes_read.value])
    return None

# ============================================================
# Step 1: Scan .text for RIP-relative indirect calls
# ============================================================
TEXT_OFF = 0x400
TEXT_SIZE = 0x18c800
TEXT_VA = 0x180001000

text = raw[TEXT_OFF : TEXT_OFF + TEXT_SIZE]
iat_targets = {}

for i in range(len(text) - 6):
    if text[i] == 0xFF and text[i+1] in (0x15, 0x25):
        disp = struct.unpack_from('<i', text, i+2)[0]
        target = TEXT_VA + i + 6 + disp
        if target not in iat_targets:
            iat_targets[target] = []
        iat_targets[target].append(TEXT_VA + i)

print(f"\nRIP-relative indirect calls: {len(iat_targets)} unique targets")

# ============================================================
# Step 2: Read at each target to see what's there
# ============================================================
# Each target in .rdata is a QWORD pointer (or JMP instruction)
api_addrs = {}  # resolved_api_addr -> list of IAT targets that point to it

for target in sorted(iat_targets.keys()):
    # Read from RUNTIME memory first (Themida decrypts at runtime)
    data = mem_read_safe(target, 8)
    if not data:
        data = file_read_bytes(target, 8)
    if not data:
        continue
    
    # Check if it's a JMP instruction
    if data[0] == 0xE9:  # jmp rel32
        disp = struct.unpack('<i', data[1:5])[0]
        dest = target + 5 + disp
        # Read what it jumps to
        jmp_data = file_read_bytes(dest, 16) or mem_read_safe(dest, 16)
        if jmp_data and jmp_data[0] == 0xFF and jmp_data[1] == 0x25:
            # jmp [rip+disp32] - read the pointer
            jmp_disp = struct.unpack_from('<i', jmp_data, 2)[0]
            ptr_addr = dest + 6 + jmp_disp
            ptr_data = file_read_bytes(ptr_addr, 8) or mem_read_safe(ptr_addr, 8)
            if ptr_data:
                api_addr = struct.unpack('<Q', ptr_data)[0]
                if api_addr and api_addr != 0:
                    api_addrs.setdefault(api_addr, []).append(target)
    elif data[0] == 0xFF and data[1] == 0x25:
        # jmp [rip+disp32] - the target itself is a jmp
        disp = struct.unpack_from('<i', data, 2)[0]
        ptr_addr = target + 6 + disp
        ptr_data = file_read_bytes(ptr_addr, 8) or mem_read_safe(ptr_addr, 8)
        if ptr_data:
            api_addr = struct.unpack('<Q', ptr_data)[0]
            if api_addr and api_addr != 0:
                api_addrs.setdefault(api_addr, []).append(target)
    else:
        # Treat as direct pointer
        ptr_val = struct.unpack('<Q', data)[0]
        if ptr_val and ptr_val != 0:
            api_addrs.setdefault(ptr_val, []).append(target)

print(f"Unique API addresses: {len(api_addrs)}")

# ============================================================
# Step 3: Match API addresses to function names
# ============================================================
psapi = ctypes.WinDLL('psapi')
psapi.GetMappedFileNameA.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong]
psapi.GetMappedFileNameA.restype = ctypes.c_ulong

dbghelp = ctypes.WinDLL('dbghelp')
dbghelp.SymInitialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
dbghelp.SymInitialize.restype = ctypes.c_bool
dbghelp.SymFromAddr.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p]
dbghelp.SymFromAddr.restype = ctypes.c_bool

# Initialize symbol handler
dbghelp.SymInitialize(ctypes.c_void_p(-1), None, False)

SYMBOL_INFO_SIZE = 4096
class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ctypes.c_ulong),
        ("TypeIndex", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", ctypes.c_ulong),
        ("Size", ctypes.c_ulong),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", ctypes.c_ulong),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", ctypes.c_ulong),
        ("Scope", ctypes.c_ulong),
        ("Tag", ctypes.c_ulong),
        ("NameLen", ctypes.c_ulong),
        ("MaxNameLen", ctypes.c_ulong),
        ("Name", ctypes.c_char * 256),
    ]

# Also build a lookup from common DLLs via GetProcAddress
print("\nBuilding DLL export lookup...")
dll_exports = {}  # (dll_name, func_name) -> address

common_dlls = [
    'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll',
    'crypt32.dll', 'ntdll.dll', 'shell32.dll', 'ole32.dll',
    'bcrypt.dll', 'winhttp.dll', 'vcruntime140.dll', 'msvcp140.dll',
    'gdi32.dll', 'winmm.dll', 'dbghelp.dll', 'psapi.dll',
    'iphlpapi.dll', 'secur32.dll', 'shlwapi.dll',
]

# We'll do reverse lookup: for each API address, try to find its name
# by comparing against loaded DLL bases and known exports
print("\n=== Resolving API names ===")

# Get loaded module info
mods = {}
class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("th32ModuleID", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("GlblcntUsage", ctypes.c_ulong),
        ("ProccntUsage", ctypes.c_ulong),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", ctypes.c_ulong),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]

kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.Module32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32)]
kernel32.Module32First.restype = ctypes.c_bool
kernel32.Module32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32)]
kernel32.Module32Next.restype = ctypes.c_bool

TH32CS_SNAPMODULE = 0x8
snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, os.getpid())
me32 = MODULEENTRY32()
me32.dwSize = ctypes.sizeof(MODULEENTRY32)

if kernel32.Module32First(snap, ctypes.byref(me32)):
    while True:
        mods[me32.modBaseAddr] = {
            'name': me32.szModule.decode('utf-8', errors='ignore'),
            'size': me32.modBaseSize,
        }
        if not kernel32.Module32Next(snap, ctypes.byref(me32)):
            break
kernel32.CloseHandle(snap)

# Now resolve each API address
api_names = {}
for api_addr in sorted(api_addrs.keys()):
    # Find which module this address belongs to
    for mod_base in sorted(mods.keys(), key=lambda x: x or 0, reverse=True):
        if mod_base and mod_base <= api_addr < mod_base + mods[mod_base]['size']:
            mod_name = mods[mod_base]['name']
            rva = api_addr - mod_base
            offset_hex = f"+0x{rva:X}"
            
            # Try SymFromAddr
            sym_info = SYMBOL_INFO()
            sym_info.SizeOfStruct = ctypes.sizeof(SYMBOL_INFO)
            sym_info.MaxNameLen = 256
            displacement = ctypes.c_ulonglong(0)
            
            if dbghelp.SymFromAddr(ctypes.c_void_p(-1), api_addr, ctypes.byref(displacement), ctypes.byref(sym_info)):
                func_name = sym_info.Name.decode('utf-8', errors='ignore')
                api_names[api_addr] = f"{mod_name}!{func_name}"
            else:
                api_names[api_addr] = f"{mod_name}{offset_hex}"
            break
    else:
        api_names[api_addr] = f"0x{api_addr:X}"

# For unresolved names (just module+offset), try GetProcAddress on common DLLs
for api_addr, name in list(api_names.items()):
    if name.startswith('0x') and '+' not in name:
        continue  # Can't resolve
    if '+' not in name.split('!')[-1]:
        continue  # Already has function name
    
    mod_name = name.split('!')[0].split('+')[0]
    rva_str = name.split('+')[-1] if '+' in name.split('!')[-1] else name.split('+')[-1]
    
    # Skip if we can't parse
    try:
        pass
    except:
        pass

# ============================================================
# Step 4: Output results
# ============================================================

# Group by module
by_module = {}
for api_addr, refs in api_addrs.items():
    name = api_names.get(api_addr, f"UNKNOWN 0x{api_addr:X}")
    mod = name.split('!')[0]
    if mod not in by_module:
        by_module[mod] = []
    total_calls = sum(len(iat_targets.get(t, [])) for t in refs)
    by_module[mod].append((name, api_addr, total_calls, len(refs)))

# Sort by total call count
print("\n" + "=" * 70)
print("RECONSTRUCTED IMPORT TABLE")
print("=" * 70)

for mod in sorted(by_module.keys(), key=lambda m: sum(x[2] for x in by_module[m]), reverse=True):
    entries = sorted(by_module[mod], key=lambda x: x[2], reverse=True)
    print(f"\n--- {mod} ({sum(x[2] for x in entries)} total calls) ---")
    for name, addr, calls, refs in entries[:20]:
        print(f"  [{calls:4d} calls] {name}")

print(f"\n{'=' * 70}")
print(f"Total unique APIs: {len(api_addrs)}")
print(f"Total modules: {len(by_module)}")
