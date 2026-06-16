#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <nmmintrin.h>
#include <vector>
#include <string>
#include <cstdint>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
static pNtQueryInformationProcess NtQIP = nullptr;
static pNtSetInformationThread NtSIT = nullptr;
static pNtQuerySystemInformation NtQSI = nullptr;
static void ResolveNtApi() {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    NtQIP = (pNtQueryInformationProcess)GetProcAddress(h, "NtQueryInformationProcess");
    NtSIT = (pNtSetInformationThread)GetProcAddress(h, "NtSetInformationThread");
    NtQSI = (pNtQuerySystemInformation)GetProcAddress(h, "NtQuerySystemInformation");
}
static PPEB GetPeb() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}
static bool Check_BeingDebugged() {
    return GetPeb()->BeingDebugged != 0;
}
static bool Check_NtGlobalFlag() {
#ifdef _WIN64
    DWORD flag = *(PDWORD)((PBYTE)GetPeb() + 0xBC);
#else
    DWORD flag = *(PDWORD)((PBYTE)GetPeb() + 0x68);
#endif
    return (flag & 0x70) != 0;
}
static bool Check_HeapFlags() {
    PVOID heap = GetProcessHeap();
    if (!heap) return false;
#ifdef _WIN64
    DWORD flags = *(PDWORD)((PBYTE)heap + 0x70);
    DWORD forceFlags = *(PDWORD)((PBYTE)heap + 0x74);
#else
    DWORD flags = *(PDWORD)((PBYTE)heap + 0x40);
    DWORD forceFlags = *(PDWORD)((PBYTE)heap + 0x44);
#endif
    return (forceFlags != 0) || ((flags & ~HEAP_GROWABLE) != 0);
}
static bool Check_IsDebuggerPresent() {
    return IsDebuggerPresent() != 0;
}
static bool Check_RemoteDebugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != 0;
}
static bool Check_DebugPort() {
    if (!NtQIP) return false;
    DWORD_PTR port = 0;
    NTSTATUS s = NtQIP(GetCurrentProcess(), 7, &port, sizeof(port), nullptr);
    return s == 0 && port != 0;
}
static bool Check_DebugFlags() {
    if (!NtQIP) return false;
    DWORD flags = 0;
    NTSTATUS s = NtQIP(GetCurrentProcess(), 31, &flags, sizeof(flags), nullptr);
    return s == 0 && flags == 0;
}
static bool Check_DebugObjectHandle() {
    if (!NtQIP) return false;
    HANDLE obj = nullptr;
    NTSTATUS s = NtQIP(GetCurrentProcess(), 30, &obj, sizeof(obj), nullptr);
    return s == 0 && obj != nullptr;
}
static bool Check_HardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
static bool Check_SoftwareBreakpoints() {
    DWORD old;
    void* addr = (void*)Check_BeingDebugged;
    if (VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        bool isBreakpoint = (*(BYTE*)addr == 0xCC);
        VirtualProtect(addr, 1, old, &old);
        return isBreakpoint;
    }
    return false;
}
static bool Check_RDTSC() {
    unsigned __int64 t1 = __rdtsc();
    Sleep(10);
    unsigned __int64 t2 = __rdtsc();
    return (t2 - t1) > 50000000ULL;
}
static bool Check_GetTickCount() {
    DWORD start = GetTickCount();
    volatile int x = 0;
    for (int i = 0; i < 1000; ++i) x += i;
    DWORD elapsed = GetTickCount() - start;
    return elapsed > 50;
}
static bool Check_Int3Handled() {
    bool handled = true;
    __try {
        __debugbreak();
        handled = false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        handled = true;
    }
    return !handled;
}
static bool Check_DebuggerWindows() {
    HWND hwnd = FindWindowA("OLLYDBG", nullptr);
    if (hwnd) return true;
    hwnd = FindWindowA("WinDbgFrameClass", nullptr);
    if (hwnd) return true;
    hwnd = FindWindowA("QWidget", nullptr);
    if (hwnd) return true;
    hwnd = FindWindowA("Qt5QWindowIcon", nullptr);
    if (hwnd) return true;
    return false;
}
static bool Check_DebuggerProcesses() {
    static const wchar_t* names[] = {
        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe",
        L"ida64.exe", L"idag.exe", L"idag64.exe", L"idaw.exe", L"idaw64.exe",
        L"windbg.exe", L"cheatengine-x86_64.exe", L"cheatengine-i386.exe",
        L"ImmunityDebugger.exe", L"reclass.exe", L"HxD.exe", L"procmon.exe",
        L"wireshark.exe"
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto n : names) {
                if (_wcsicmp(pe.szExeFile, n) == 0) { found = true; break; }
            }
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}
static bool Check_APIHooks() {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto ntQuery = (BYTE*)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!ntQuery) return false;
    if (*ntQuery == 0xCC || *ntQuery == 0xE9 || *ntQuery == 0xEB) {
        return true;
    }
    return false;
}
struct IntegrityCheck {
    void* address = nullptr;
    std::uint32_t size = 0;
    std::uint32_t checksum = 0;
    static std::uint32_t crc32(void* data, std::size_t size) {
        std::uint32_t result = 0;
        auto p = reinterpret_cast<std::uint8_t*>(data);
        for (std::size_t i = 0; i < size; ++i)
            result = _mm_crc32_u8(result, p[i]);
        return result;
    }
    static IntegrityCheck capture() {
        IntegrityCheck ic = {};
        auto mod = (std::uintptr_t)GetModuleHandleA(nullptr);
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return ic;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(mod + dos->e_lfanew);
        auto section_hdr = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section_hdr++) {
            if (strncmp((char*)section_hdr->Name, ".text", 5) == 0) {
                ic.address = reinterpret_cast<void*>(mod + section_hdr->VirtualAddress);
                ic.size = section_hdr->Misc.VirtualSize;
                ic.checksum = crc32(ic.address, ic.size);
                break;
            }
        }
        return ic;
    }
    bool verify() const {
        auto current = crc32(address, size);
        return current == checksum;
    }
};
static IntegrityCheck g_integrity;
static bool Check_CodeIntegrity() {
    return g_integrity.address && !g_integrity.verify();
}
static void AntiDump() {
#ifdef _WIN64
    const auto peb = (PPEB)__readgsqword(0x60);
#else
    const auto peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb && peb->Ldr) {
        const auto in_load_order = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
        if (in_load_order) {
            const auto entry = CONTAINING_RECORD(in_load_order, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
            auto p_size = (PULONG)&entry->Reserved3[1];
            *p_size = (ULONG)((INT_PTR)entry->DllBase + 0x100000);
        }
    }
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (hMod) {
        DWORD old;
        if (VirtualProtect(hMod, 0x1000, PAGE_READWRITE, &old)) {
            memset(hMod, 0, 0x1000);
            VirtualProtect(hMod, 0x1000, old, &old);
        }
    }
}
static void HideThreadFromDebugger() {
    if (NtSIT) NtSIT(GetCurrentThread(), 0x11, nullptr, 0);
}
static bool Check_KernelDebugger() {
    if (!NtQSI) return false;
    struct { BOOLEAN KdEnabled; BOOLEAN KdNotPresent; } info = {};
    NTSTATUS s = NtQSI(35, &info, sizeof(info), nullptr);
    return s == 0 && info.KdEnabled && !info.KdNotPresent;
}
static bool RunAllChecks() {
    if (Check_BeingDebugged()) return true;
    if (Check_NtGlobalFlag()) return true;
    if (Check_HeapFlags()) return true;
    if (Check_IsDebuggerPresent()) return true;
    if (Check_RemoteDebugger()) return true;
    if (Check_DebugPort()) return true;
    if (Check_DebugFlags()) return true;
    if (Check_DebugObjectHandle()) return true;
    if (Check_HardwareBreakpoints()) return true;
    if (Check_SoftwareBreakpoints()) return true;
    if (Check_RDTSC()) return true;
    if (Check_GetTickCount()) return true;
    if (Check_Int3Handled()) return true;
    if (Check_DebuggerWindows()) return true;
    if (Check_DebuggerProcesses()) return true;
    if (Check_APIHooks()) return true;
    if (Check_CodeIntegrity()) return true;
    if (Check_KernelDebugger()) return true;
    return false;
}
static DWORD WINAPI MonitorThread(LPVOID) {
    while (true) {
        if (RunAllChecks()) {
            ExitProcess(0xDEAD);
        }
        Sleep(1000);
    }
    return 0;
}
int main() {
    ResolveNtApi();
    g_integrity = IntegrityCheck::capture();
    AntiDump();
    HideThreadFromDebugger();
    DWORD tid;
    HANDLE hThread = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, &tid);
    if (hThread) CloseHandle(hThread);
    if (RunAllChecks()) {
        ExitProcess(0);
    }
    return 0;
        }
        