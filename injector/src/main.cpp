#include <filesystem>
#include <windows.h>

#include "../include/console.h"
#include "../include/process.h"
#include "../include/injector.h"
#include "../log_handler.hpp"

int main(int argc, char* argv[])
{
    enable_virtual_terminal();

    if (argc < 3) {
        LOG_ERROR("Usage: injector.exe <process_name> <dll_relative_path>");
        return 1;
    }

    const std::string procName = argv[1];
    const std::string dllRelPath = argv[2];

    std::filesystem::path exeDir = std::filesystem::absolute(argv[0]).parent_path();
    std::filesystem::path dllFullPath = exeDir / dllRelPath;

    if (!std::filesystem::exists(dllFullPath)) {
        LOG_ERROR("DLL not found: " + dllFullPath.string());
        return 1;
    }

    DWORD pid = GetProcessIdByName(procName);
    if (!pid) {
        LOG_ERROR("Could not find process: " + procName);
        return 1;
    }

    LOG_INFO("Found process with PID: " + std::to_string(pid));
    LOG_INFO("DLL: " + dllRelPath);

    if (InjectDLL(pid, dllFullPath.string()))
        LOG_SUCCESS("Injection successful!");
    else
        LOG_ERROR("Injection failed.");

    Sleep(5000);
    return 0;
}
