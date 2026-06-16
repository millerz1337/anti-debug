#include "anti-debug.hpp"
#include <windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

namespace AntiDebug {

    bool CheckIsDebuggerPresent() {
        if (IsDebuggerPresent()) {
            return true;
        }
        return false;
    }

    bool CheckRemoteDebugger() {
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
            return true;
        }
        return false;
    }

    bool CheckNtGlobalFlag() {
        PEB* pPeb = (PEB*)__readgsqword(0x60);
        PDWORD pNtGlobalFlag = (PDWORD)((PBYTE)pPeb + 0xBC);
        if (*pNtGlobalFlag & 0x70) {
            return true;
        }
        return false;
    }

    bool CheckHeapFlags() {
        PEB* pPeb = (PEB*)__readgsqword(0x60);
        PVOID pHeapBase = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb + 0x30);
        DWORD dwHeapFlagsOffset = 0x70;
        DWORD dwHeapForceFlagsOffset = 0x74;

        PDWORD pdwHeapFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset);
        PDWORD pdwHeapForceFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);

        if (*pdwHeapFlags & ~HEAP_GROWABLE || *pdwHeapForceFlags != 0) {
            return true;
        }
        return false;
    }

    bool CheckDebugPort() {
        HANDLE hProcess = GetCurrentProcess();
        DWORD dwDebugPort = 0;
        
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            DWORD ProcessInformationLength,
            PDWORD ReturnLength
        );

        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), 
                "NtQueryInformationProcess"
            );

        if (NtQueryInformationProcess) {
            NTSTATUS status = NtQueryInformationProcess(
                hProcess, 
                7, // ProcessDebugPort
                &dwDebugPort, 
                sizeof(DWORD), 
                NULL
            );

            if (status == 0 && dwDebugPort != 0) {
                return true;
            }
        }
        return false;
    }

    bool CheckHardwareBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                return true;
            }
        }
        return false;
    }

    bool CheckTiming() {
        DWORD64 start = GetTickCount64();
        Sleep(10);
        DWORD64 end = GetTickCount64();
        
        if ((end - start) > 100) {
            return true;
        }
        return false;
    }

    bool CheckParentProcess() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32);

        DWORD currentPID = GetCurrentProcessId();
        DWORD parentPID = 0;

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == currentPID) {
                    parentPID = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        if (parentPID != 0 && Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == parentPID) {
                    char parentName[MAX_PATH];
                    size_t convertedChars = 0;
                    wcstombs_s(&convertedChars, parentName, MAX_PATH, pe32.szExeFile, _TRUNCATE);
                    
                    std::string parentNameStr = parentName;
                    std::transform(parentNameStr.begin(), parentNameStr.end(), parentNameStr.begin(), ::tolower);
                    
                    if (parentNameStr.find("devenv") != std::string::npos ||
                        parentNameStr.find("x64dbg") != std::string::npos ||
                        parentNameStr.find("x32dbg") != std::string::npos ||
                        parentNameStr.find("ollydbg") != std::string::npos ||
                        parentNameStr.find("ida") != std::string::npos ||
                        parentNameStr.find("windbg") != std::string::npos) {
                        
                        CloseHandle(hSnapshot);
                        return true;
                    }
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    void Initialize() {
        SetLastError(0);
    }

    bool RunAllChecks() {
        if (CheckIsDebuggerPresent()) return true;
        if (CheckRemoteDebugger()) return true;
        if (CheckDebugPort()) return true;
        if (CheckNtGlobalFlag()) return true;
        if (CheckHeapFlags()) return true;
        if (CheckHardwareBreakpoints()) return true;
        if (CheckTiming()) return true;
        if (CheckParentProcess()) return true;
        
        return false;
    }
}
