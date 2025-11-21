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

    const auto clientBase = reinterpret_cast<uintptr_t>(GetModuleHandleA("client.dll"));
    const uintptr_t dwEntityList = clientBase + 0x96d848;
    std::cout << "dwEntityList: 0x" << dwEntityList << std::endl;

    while (true)
    {
        for (int i = 0; i < 4028; i++)
        {
            uintptr_t entity = *reinterpret_cast<uintptr_t*>(dwEntityList + i * 0x20);
            if (!entity) continue;

            std::cout << "Entity[" << i << "]" << "\n";
        }

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