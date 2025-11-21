#include <windows.h>

DWORD WINAPI MainThread(const LPVOID param)
{
    const auto hModule = static_cast<HMODULE>(param);
    MessageBoxA(nullptr, "Injected!", "DLL", MB_OK);
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(const HMODULE hModule, const DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}
