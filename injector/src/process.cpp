#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include "process.h"
#include "../log_handler.hpp"

DWORD GetProcessIdByName(const std::string& name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        LOG_ERROR("CreateToolhelp32Snapshot failed.");
        return 0;
    }

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, name.c_str()) == 0) {
                CloseHandle(snap);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return 0;
}