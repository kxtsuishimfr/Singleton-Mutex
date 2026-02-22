#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <set>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

std::set<HANDLE> g_KilledHandleValues; 

void UnlockRoblox() {
    auto NtQuerySystemInformation = (decltype(&::NtQuerySystemInformation))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    auto NtQueryObject = (decltype(&::NtQueryObject))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);

    while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, pHandleInfo, size, &size) == STATUS_INFO_LENGTH_MISMATCH) {
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, size);
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        auto& handleEntry = pHandleInfo->Handles[i];

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handleEntry.UniqueProcessId);
        if (!hProcess) continue;

        char procPath[MAX_PATH];
        if (GetProcessImageFileNameA(hProcess, procPath, MAX_PATH)) {
            if (strstr(procPath, "RobloxPlayerBeta.exe")) {
                HANDLE hDup = NULL;
                // Query name
                if (DuplicateHandle(hProcess, (HANDLE)handleEntry.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    ULONG nameLen = 2048;
                    POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)malloc(nameLen);

                    if (NtQueryObject(hDup, (OBJECT_INFORMATION_CLASS)1, pNameInfo, nameLen, &nameLen) == 0) {
                        if (pNameInfo->Name.Buffer && wcsstr(pNameInfo->Name.Buffer, L"ROBLOX_singletonEvent")) {

                            HANDLE hStolen = NULL;
                            if (DuplicateHandle(hProcess, (HANDLE)handleEntry.HandleValue, GetCurrentProcess(), &hStolen, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
                                CloseHandle(hStolen);
                                std::wcout << L"[!] Removed Mutex in PID: " << handleEntry.UniqueProcessId << std::endl;
                            }
                        }
                    }
                    free(pNameInfo);
                    CloseHandle(hDup);
                }
            }
        }
        CloseHandle(hProcess);
    }
    free(pHandleInfo);
}

int main() {
    std::cout << "Waiting for Roblox..." << std::endl;
    while (true) {
        UnlockRoblox();
        Sleep(100);
    }
    return 0;
}
