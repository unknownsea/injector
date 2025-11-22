#include <cstdint>
#include <windows.h>
#include <iostream>

DWORD WINAPI MainThread(LPVOID param)
{
    const auto hModule = static_cast<HMODULE>(param);

    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "[DLL] Press END to unload.\n";

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            std::cout << "[DLL] Unloading...\n";
            break;
        }

        Sleep(500);
    }

    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}