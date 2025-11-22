/*

This took to long ngl but ty chatgpt for going back in fourth with me until actually
fixing it for me like a good boy, i lowkey have devine intellect.

*/

#include <cstdint>
#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <ostream>
#include <thread>

struct KeyButton // taken from a2x/cs2-dumper
{
    uint64_t pad_0000;
    const char* name;      // 0x08
    uint8_t pad_0010[0x20];
    uint32_t state;        // 0x30
    uint8_t pad_0034[0x54];
    KeyButton* next;       // 0x88
};

struct ButtonInfo
{
    std::string name;
    KeyButton* ptr;
    uintptr_t stateOffsetRVA;
    uint32_t state;
};

std::vector<ButtonInfo> g_Buttons;

bool IsValidPtr(const void* ptr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!ptr) return false;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    return (mbi.State & MEM_COMMIT) != 0;
}

void BuildPattern(const char* pat, std::vector<uint8_t>& bytes, std::string& mask)
{
    bytes.clear();
    mask.clear();
    while (*pat)
    {
        if (*pat == ' ') { pat++; continue; }
        if (*pat == '?') { bytes.push_back(0); mask.push_back('?'); if (pat[1] == '?') pat++; pat++; continue; }
        char b[3] = { pat[0], pat[1], 0 };
        bytes.push_back((uint8_t)strtoul(b, nullptr, 16));
        mask.push_back('x');
        pat += 2;
    }
}

uintptr_t PatternScan(uint8_t* base, size_t size, const std::vector<uint8_t>& pat, const std::string& mask)
{
    size_t len = mask.size();
    for (size_t i = 0; i <= size - len; i++)
    {
        bool ok = true;
        for (size_t j = 0; j < len; j++)
            if (mask[j] == 'x' && base[i + j] != pat[j]) { ok = false; break; }
        if (ok) return (uintptr_t)(base + i);
    }
    return 0;
}

void DumpButtons(HMODULE hClient)
{
    auto dos = (PIMAGE_DOS_HEADER)hClient;
    auto nt = (PIMAGE_NT_HEADERS)((uint8_t*)hClient + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    uint8_t* textBase = nullptr;
    DWORD textSize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!strcmp((char*)sec->Name, ".text"))
        {
            textBase = (uint8_t*)hClient + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize;
            break;
        }
    }

    const char* sig = "48 8B 15 ?? ?? ?? ?? 48 85 D2 74 ?? 48 8B 02 48 85 C0";
    std::vector<uint8_t> pat;
    std::string mask;
    BuildPattern(sig, pat, mask);

    uintptr_t addr = PatternScan(textBase, textSize, pat, mask);
    if (!addr) return;

    int32_t rel = *(int32_t*)(addr + 3);
    uintptr_t g_ButtonList = addr + 7 + rel;

    KeyButton** firstPtr = (KeyButton**)g_ButtonList;
    if (!IsValidPtr(firstPtr)) return;

    KeyButton* cur = *firstPtr;

    g_Buttons.clear();
    while (cur && IsValidPtr(cur))
    {
        ButtonInfo info;
        info.name = (IsValidPtr((void*)cur->name) && cur->name) ? cur->name : "unnamed";
        info.ptr = cur;
        info.stateOffsetRVA = (uintptr_t)&cur->state - (uintptr_t)hClient;
        info.state = cur->state;

        g_Buttons.push_back(info);

        if (!IsValidPtr(cur->next) || cur->next == nullptr) break;
        cur = cur->next;
    }
}

DWORD WINAPI MainThread(LPVOID param)
{
    const auto hModule = static_cast<HMODULE>(param);

    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    HMODULE hClient = nullptr;
    while (!hClient)
    {
        hClient = GetModuleHandleA("client.dll");
        Sleep(50);
    }

    DumpButtons(hClient);

    auto jump = std::ranges::find_if(g_Buttons, [](const ButtonInfo& b) {
        return b.name == "jump";
    });

    std::cout << "[DLL] Press END to unload.\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (GetAsyncKeyState(VK_END) & 1)
        {
            std::cout << "[DLL] Unloading...\n";
            break;
        }

        if (GetAsyncKeyState(VK_SPACE)) {
            if (IsValidPtr(jump->ptr)) {
                jump->ptr->state = 65537;
                Sleep(1);
                jump->ptr->state = 256;
            }
        }
    }

    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd)
    {
        FreeConsole();
        PostMessage(consoleWnd, WM_CLOSE, 0, 0);
    }

    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(mod);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}