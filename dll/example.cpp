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

    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd)
    {
        FreeConsole();
        PostMessage(consoleWnd, WM_CLOSE, 0, 0);
    }

    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
        default:;
    }

    return TRUE;
}