#include "schema.h"
#include <windows.h>
#include <iostream>
#include <cstdint>

static bool IsReadable(void* addr, SIZE_T size = 1)
{
    if (!addr)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    DWORD prot = mbi.Protect & ~PAGE_GUARD;
    return prot == PAGE_READONLY || prot == PAGE_READWRITE ||
           prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE;
}

using CreateInterfaceFn = void* (__cdecl*)(const char* name, int* returnCode);

static void* g_SchemaSystem = nullptr;

bool schema::setup()
{
    HMODULE dll = GetModuleHandleA("schemasystem.dll");
    if (!dll)
    {
        std::cout << "[Schema] schemasystem.dll not loaded\n";
        return false;
    }

    auto CI = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(dll, "CreateInterface"));
    if (!CI)
    {
        std::cout << "[Schema] CreateInterface not found\n";
        return false;
    }

    g_SchemaSystem = CI("SchemaSystem_001", nullptr);
    if (!g_SchemaSystem)
    {
        std::cout << "[Schema] CreateInterface returned NULL\n";
        return false;
    }

    std::cout << "[Schema] g_SchemaSystem = " << g_SchemaSystem << "\n";
    return true;
}

void schema::DumpScopes()
{
    if (!g_SchemaSystem)
    {
        std::cout << "[Schema] g_SchemaSystem is null\n";
        return;
    }

    // vecTypeScopes is at offset 0x188 from ISchemaSystem base
    uintptr_t scopesAddr = (uintptr_t)g_SchemaSystem + 0x188;

    struct CUtlVectorFixed
    {
        void** Data;  // pointer to array of CSchemaSystemTypeScope*
        int Size;     // number of used elements
        int Capacity; // irrelevant
    };

    auto scopes = reinterpret_cast<CUtlVectorFixed*>(scopesAddr);

    if (!IsReadable(scopes, sizeof(CUtlVectorFixed)))
    {
        std::cout << "[Schema] vecTypeScopes unreadable\n";
        return;
    }

    if (scopes->Size <= 0 || scopes->Size > 2048)
    {
        std::cout << "[Schema] Invalid scope size: " << scopes->Size << "\n";
        return;
    }

    std::cout << "[Schema] Total scopes: " << scopes->Size << "\n";

    for (int i = 0; i < scopes->Size; i++)
    {
        void* scope = scopes->Data[i];
        if (!scope || !IsReadable(scope))
        {
            std::cout << "[Schema] Scope[" << i << "] unreadable\n";
            continue;
        }

        // name is ALWAYS at offset 0x8 in CSchemaSystemTypeScope
        const char* name = *(const char**)((uintptr_t)scope + 0x8);

        if (name && IsReadable((void*)name))
            std::cout << "[Schema] Scope[" << i << "]: " << name << "\n";
        else
            std::cout << "[Schema] Scope[" << i << "]: <invalid name>\n";
    }
}
