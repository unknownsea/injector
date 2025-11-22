#include <windows.h>
#include <string>
#include "../include/injector.h"
#include "../include/hijack.h"
#include "../log_handler.hpp"
#include "../include/map.h"
#include <filesystem>
#include <vector>
#include <fstream>

bool loadFileToMemory(const std::string& path, std::vector<uint8_t>& outBuffer)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return false;

    std::streamsize size = file.tellg();
    if (size <= 0)
        return false;

    outBuffer.resize(size);
    file.seekg(0, std::ios::beg);

    return file.read(reinterpret_cast<char*>(outBuffer.data()), size).good();
}

bool InjectDLL(DWORD pid, const std::string& dllPath)
{
    HANDLE hProcess = HijackProcessHandle(pid);

    if (!hProcess)
    {
        LOG_ERROR("Hijack failed, attempting OpenProcess...");

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
        {
            LOG_ERROR("OpenProcess also failed. Cannot inject.");
            return false;
        }

        LOG_SUCCESS("Successfully opened process using normal OpenProcess.");
    }
    else
    {
        LOG_SUCCESS("Successfully hijacked a valid process handle!");
    }

    std::vector<uint8_t> buffer;

    std::string absDllPath = std::filesystem::absolute(dllPath).string();

    if (!loadFileToMemory(absDllPath, buffer))
    {
        LOG_ERROR("Failed to read DLL file into memory.");
        CloseHandle(hProcess);
        return false;
    }

    if (!ManualMapDLL(hProcess, buffer.data(), buffer.size()))
    {
        LOG_ERROR("Manual mapping failed.");
        CloseHandle(hProcess);
        return false;
    }

    LOG_SUCCESS("Manual mapping successful!");
    CloseHandle(hProcess);
    return true;
}