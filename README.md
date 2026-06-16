# anti-debug

collection of anti-debugging techniques for windows x64. each check returns true on detection, false otherwise. no logging, no exit calls - pure detection logic for integration into your protection scheme.

## implementation

```cpp
#include "anti-debug.hpp"

int main() {
    AntiDebug::Initialize();
    
    if (AntiDebug::RunAllChecks()) {
        return 1; // debugger detected
    }
    
    // your protected code here
    
    return 0;
}
```

alternatively, check individual techniques:

```cpp
if (AntiDebug::CheckIsDebuggerPresent()) {
    // handle detection
}

if (AntiDebug::CheckHardwareBreakpoints()) {
    // handle detection
}
```

## detection techniques

### IsDebuggerPresent

standard kernel32 api call. checks `BeingDebugged` flag in PEB at offset 0x02. trivial to bypass via PEB patching or api hooking.

```cpp
bool CheckIsDebuggerPresent()
```

### CheckRemoteDebuggerPresent

kernel32 wrapper around `NtQueryInformationProcess`. checks if debugger attached to current process. can be hooked or bypassed by zeroing the output parameter.

```cpp
bool CheckRemoteDebugger()
```

### NtQueryInformationProcess

direct ntdll call with `ProcessDebugPort` (0x07) class. returns -1 if debugger present, 0 otherwise. more reliable than kernel32 wrappers but still hookable.

```cpp
bool CheckDebugPort()
```

### NtGlobalFlag

reads PEB + 0xBC. debugger presence sets flags `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10), `FLG_HEAP_ENABLE_FREE_CHECK` (0x20), `FLG_HEAP_VALIDATE_PARAMETERS` (0x40). combined mask 0x70.

bypass: patch PEB before check or clear flags via debugger script.

```cpp
bool CheckNtGlobalFlag()
```

### Heap Flags

process heap created differently under debugger. checks `Flags` (offset 0x70) and `ForceFlags` (offset 0x74) in heap structure.

normal execution: `Flags = HEAP_GROWABLE (0x02)`, `ForceFlags = 0`  
under debugger: different values set by system

bypass: manual heap flag patching before check execution.

```cpp
bool CheckHeapFlags()
```

### Hardware Breakpoints

reads debug registers DR0-DR3 via `GetThreadContext`. non-zero value indicates hardware breakpoint set.

limitation: only detects current thread. multi-threaded debuggers can avoid detection.

bypass: clear DR registers before thread context query or hook the api.

```cpp
bool CheckHardwareBreakpoints()
```

### Timing Check

measures execution time of known operation. debugger overhead (single-stepping, breakpoints) causes timing discrepancies.

current threshold: 100ms tolerance for 10ms sleep. adjust based on your requirements and target environment.

bypass: manipulate timing apis, use time-stretching plugins, or patch the check entirely.

```cpp
bool CheckTiming()
```

### Parent Process Analysis

enumerates process tree via `CreateToolhelp32Snapshot`. checks if parent process matches known debugger executables.

detected names: devenv, x64dbg, x32dbg, ollydbg, ida, windbg

limitation: fails if process spawned from modified launcher or injected into legitimate process.

bypass: spawn from explorer, modify process parent via handle inheritance, or patch process name in memory.

```cpp
bool CheckParentProcess()
```

## technical details

- all PEB access via `__readgsqword(0x60)` on x64
- requires ntdll.lib linkage for `NtQueryInformationProcess`
- compatible with MSVC compiler only due to intrinsics
- no exception handling - assumes valid memory access

## bypassing considerations

none of these checks are bulletproof. competent reverser can defeat them via:

1. api hooking (kernel32, ntdll)
2. peb/teb structure patching
3. debugger plugins (scyllahide, hideoz)
4. custom debugger with anti-detection
5. virtualization/emulation layer

use multiple checks, add code obfuscation, implement custom checks based on your threat model. layered approach increases analysis time.

## build

msvc x64 release configuration required.

```
cl /O2 /EHsc anti-debug.cxx your_code.cpp /link ntdll.lib
```

## notes

no telemetry, no logging, no dependencies beyond windows sdk. integrate into your protection workflow however you need. checks return boolean - you decide what happens on detection.
