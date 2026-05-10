@echo off
REM =========================================
REM Launch x64dbg for ersc.dll analysis
REM =========================================
REM Modes:
REM   1 = Unpacking (loaddll.exe + Themida profile)
REM   2 = Dynamic Trace (loaddll.exe + trace script)
REM   3 = Elden Ring attach (manual)
REM =========================================

set X64DBG=%~dp0x64dbg\release\x64\x64dbg.exe
set LOADER=%~dp0x64dbg\release\x64\loaddll.exe
set DLL=%~dp0ersc.dll
set UNPACK_SCRIPT=%~dp0unpack_ersc.txt
set TRACE_PLAN=%~dp0x64dbg_trace_plan.md

if not exist "%X64DBG%" (
    echo ERROR: x64dbg.exe not found!
    echo Expected: %X64DBG%
    pause
    exit /b 1
)

echo =========================================
echo ersc.dll Analysis Launcher
echo =========================================
echo.
echo Select mode:
echo   1 = Unpacking (Themida profile + loaddll)
echo   2 = Dynamic Trace (breakpoints on key functions)
echo   3 = Open x64dbg only (manual)
echo.
set /p MODE="Enter 1, 2, or 3: "

if "%MODE%"=="1" (
    echo.
    echo === UNPACKING MODE ===
    echo.
    echo x64dbg:  %X64DBG%
    echo Target:  %DLL%
    echo.
    echo MANUAL STEPS:
    echo   1. Plugins ^> ScyllaHide ^> Profiles ^> Themida
    echo   2. File ^> Open ^> loaddll.exe
    echo      Arguments: %DLL%
    echo      Working Directory: %~dp0
    echo   3. Script panel ^> Load ^> %UNPACK_SCRIPT%
    echo   4. After OEP found: Scylla ^> IAT Autosearch ^> Dump ^> Fix
    echo.
)

if "%MODE%"=="2" (
    echo.
    echo === DYNAMIC TRACE MODE ===
    echo.
    echo x64dbg:  %X64DBG%
    echo Target:  %DLL%
    echo.
    echo MANUAL STEPS:
    echo   1. Plugins ^> ScyllaHide ^> Profiles ^> Themida
    echo   2. File ^> Open ^> loaddll.exe
    echo      Arguments: %DLL%
    echo      Working Directory: %~dp0
    echo   3. Set breakpoints (copy-paste each line to command bar):
    echo.
    echo      ; ---- Session Registry ----
    echo      bp ersc.dll + 0x26eb0
    echo      bp ersc.dll + 0x8032a
    echo.
    echo      ; ---- Voice Chat ----
    echo      bp ersc.dll + 0xa47a0
    echo.
    echo      ; ---- Init / Game Logic ----
    echo      bp ersc.dll + 0x3cc30
    echo      bp ersc.dll + 0x96960
    echo      bp ersc.dll + 0x9d450
    echo.
    echo      ; ---- Export Entry ----
    echo      bp ersc.dll + 0x2b00
    echo.
    echo   4. F9 to run. When bp hits:
    echo      - d rcx        (dump structure at rcx)
    echo      - ? rcx - ersc.dll  (calculate offset)
    echo      - Watch call stack
    echo.
    echo   See %TRACE_PLAN% for detailed analysis plan.
    echo.
)

echo =========================================
echo Press any key to open x64dbg...
pause >nul

start "" "%X64DBG%"
