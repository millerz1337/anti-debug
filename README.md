# Anti-Debug

A comprehensive Windows anti-debugging library implementing 18 different detection techniques.

## Features

This library provides multiple layers of debugger detection:

**PEB-based checks**
- BeingDebugged flag
- NtGlobalFlag inspection
- Heap flags anomaly detection

**API-based checks**
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- NtQueryInformationProcess (DebugPort, DebugFlags, DebugObjectHandle)

**Breakpoint detection**
- Hardware breakpoints (DR0-DR3 registers)
- Software breakpoints (INT3/0xCC instruction scanning)

**Timing analysis**
- RDTSC instruction timing
- GetTickCount timing anomalies

**Process/Window enumeration**
- Debugger process detection (x64dbg, IDA Pro, OllyDbg, WinDbg, Cheat Engine, etc.)
- Debugger window class detection

**Code integrity**
- CRC32 checksumming of .text section
- API hook detection (NtQueryInformationProcess patching)

**Protection mechanisms**
- Anti-dump (PE header corruption)
- Hidden monitoring thread
- Kernel debugger detection

## Usage

```cpp
#include "anti-debug.cxx"

int main() {
    ResolveNtApi();
    g_integrity = IntegrityCheck::capture();
    AntiDump();
    HideThreadFromDebugger();
    
    if (RunAllChecks()) {
        // Debugger detected
        ExitProcess(0);
    }
    
    // Your application code
    return 0;
}
```

## Building

Requires:
- Windows SDK
- MSVC or compatible compiler
- C++17 or later

Link against: `ntdll.lib`, `psapi.lib`

Compile with intrinsics support for RDTSC and CRC32 instructions.

## Technical Details

The implementation uses both documented and undocumented Windows APIs to detect debugging attempts. The monitoring thread continuously validates process state and code integrity at runtime.

## Notes

This code is provided for educational and research purposes. Use responsibly and in compliance with applicable laws and terms of service.

## License

MIT
