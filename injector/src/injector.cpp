#include <windows.h>
#include <string>
#include "../include/injector.h"
#include "../include/hijack.h"
#include "../log_handler.hpp"

bool InjectDLL(DWORD pid, const std::string& dllPath)
{
    // HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hProcess = HijackProcessHandle(pid);
    if (!hProcess) {
        LOG_ERROR("Failed to open target process.");
        return false;
    }

    LPVOID remotePath = VirtualAllocEx(
        hProcess, nullptr, dllPath.size() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!remotePath) {
        LOG_ERROR("Failed to allocate memory in remote process.");
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        LOG_ERROR("Failed to write DLL path.");
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")
    );

    if (!loadLib) {
        LOG_ERROR("Failed to resolve LoadLibraryA.");
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0, loadLib, remotePath, 0, nullptr
    );

    if (!hThread) {
        LOG_ERROR("Failed to create remote thread.");
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}
