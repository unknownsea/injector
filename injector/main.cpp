#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <filesystem>

DWORD GetProcessIdByName(const std::string& name) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry;
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

bool InjectDLL(DWORD pid, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open target process.\n";
        return false;
    }

    LPVOID alloc = VirtualAllocEx(
        hProcess, nullptr, dllPath.size() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!alloc) {
        std::cout << "[-] Failed to allocate memory.\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, alloc, dllPath.c_str(),
                            dllPath.size() + 1, nullptr)) {
        std::cout << "[-] Failed to write DLL path.\n";
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    const auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")
    );

    if (!loadLib) {
        std::cout << "[-] Failed to get LoadLibraryA.\n";
        CloseHandle(hProcess);
        return false;
    }

    const HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLib,
        alloc, 0, nullptr
    );

    if (!hThread) {
        std::cout << "[-] Failed to create remote thread.\n";
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

int main(const int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage:\n"
                     "program.exe <process_name> <dll_path>";
        return 1;
    }

    std::string procName = argv[1];
    std::string dllRelPath = argv[2];

    // resolve full DLL path relative to injector exe
    std::filesystem::path exeDir = std::filesystem::absolute(argv[0]).parent_path();
    std::filesystem::path fullDllPath = exeDir / dllRelPath;

    if (!std::filesystem::exists(fullDllPath)) {
        std::cout << "[-] DLL not found: " << fullDllPath.string() << "\n";
        return 1;
    }

    const DWORD pid = GetProcessIdByName(procName);
    if (pid == 0) {
        std::cout << "[-] Could not find running process: " << procName << "\n";
        return 1;
    }

    std::cout << "[+] Found process PID: " << pid << "\n";
    std::cout << "[+] DLL full path: " << fullDllPath.string() << "\n";

    if (InjectDLL(pid, fullDllPath.string()))
        std::cout << "[+] Injection successful!\n";
    else
        std::cout << "[-] Injection failed.\n";

    return 0;
}
