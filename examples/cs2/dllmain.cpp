#include <windows.h>
#include <thread>
#include <chrono>
#include <iostream>

#include "sdk/schema.h"

DWORD WINAPI MainThread(LPVOID lp)
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);

    std::cout << "[DLL] Initializing...\n";

    while (!GetModuleHandleA("client.dll"))
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    while (!GetModuleHandleA("schemasystem.dll"))
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (!schema::setup())
    {
        std::cout << "[Schema] Failed to initialize.\n";
    }
    else
    {
        std::cout << "[Schema] Initialized!\n";
        schema::DumpScopes();
    }

    std::cout << "Press END to unload...\n";

    while (!(GetAsyncKeyState(VK_END) & 1))
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    fclose(stdout);
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)lp, 0);
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