#include <windows.h>
#include <winnt.h>
#include "../log_handler.hpp"

struct ManualMapStub {
    FARPROC entry;
    HMODULE module;
};

unsigned char stubCode[] = {
    0x48, 0x83, 0xEC, 0x28,                   // sub RSP, 0x28
    0x48, 0x8B, 0x41, 0x00,                   // mov RAX, [RCX] (entry)
    0x48, 0x8B, 0x51, 0x08,                   // mov RDX, [RCX+8] (hModule)
    0xBA, 0x01, 0x00, 0x00, 0x00,             // mov EDX, DLL_PROCESS_ATTACH
    0x33, 0xC9,                               // xor ECX, ECX (lpReserved = NULL)
    0xFF, 0xD0,                               // call RAX
    0x48, 0x83, 0xC4, 0x28,                   // add RSP, 0x28
    0xC3                                      // ret
};

static void WriteMem(HANDLE hp, LPVOID dst, LPCVOID src, SIZE_T size)
{
    WriteProcessMemory(hp, dst, src, size, nullptr);
}

static uintptr_t RVAtoOffset(uintptr_t rva, const IMAGE_NT_HEADERS64* nt, const uint8_t* dll)
{
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        const auto& s = sec[i];
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize)
            return (rva - s.VirtualAddress) + s.PointerToRawData;
    }
    return 0;
}

bool ManualMapDLL(HANDLE hProcess, const uint8_t* dll, size_t dllSize)
{
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dll);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(dll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    LPVOID remoteBase = VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase), imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase)
    {
        remoteBase = VirtualAllocEx(hProcess, nullptr, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) return false;
    }

    WriteMem(hProcess, remoteBase, dll, nt->OptionalHeader.SizeOfHeaders);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        const IMAGE_SECTION_HEADER& s = sec[i];
        if (s.SizeOfRawData == 0) continue;
        WriteMem(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + s.VirtualAddress), dll + s.PointerToRawData, s.SizeOfRawData);
    }

    uintptr_t delta = reinterpret_cast<uintptr_t>(remoteBase) - nt->OptionalHeader.ImageBase;
    if (delta != 0)
    {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.Size)
        {
            uintptr_t relocOffset = RVAtoOffset(dir.VirtualAddress, nt, dll);
            if (!relocOffset) return false;
            auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(const_cast<uint8_t*>(dll) + relocOffset);
            uintptr_t end = relocOffset + dir.Size;

            while (static_cast<uintptr_t>(reinterpret_cast<uint8_t *>(reloc) - dll) < end)
            {
                if (reloc->SizeOfBlock == 0) break;
                uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = reinterpret_cast<WORD *>(reinterpret_cast<uint8_t *>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
                for (uint32_t i = 0; i < count; i++)
                {
                    WORD entry = list[i];
                    uint16_t type = entry >> 12;
                    uint16_t offset = entry & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        uintptr_t rva = reloc->VirtualAddress + offset;
                        uintptr_t fileOff = RVAtoOffset(rva, nt, dll);
                        if (!fileOff) continue;
                        uintptr_t* patchAddr = (uintptr_t*)(dll + fileOff);
                        uintptr_t newVal = *patchAddr + delta;
                        WriteMem(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + rva), &newVal, sizeof(uintptr_t));
                    }
                }
                reloc = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<uint8_t *>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size)
    {
        uintptr_t impOffset = RVAtoOffset(impDir.VirtualAddress, nt, dll);
        if (!impOffset) return false;
        auto impDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(dll + impOffset);
        while (impDesc->Name)
        {
            uintptr_t nameOff = RVAtoOffset(impDesc->Name, nt, dll);
            if (!nameOff) return false;
            const char* dllName = reinterpret_cast<const char*>(dll + nameOff);
            HMODULE mod = LoadLibraryA(dllName);
            if (!mod) return false;

            uintptr_t thunkRVA = impDesc->FirstThunk;
            uintptr_t origRVA = impDesc->OriginalFirstThunk;
            auto orig = reinterpret_cast<const IMAGE_THUNK_DATA64*>(dll + RVAtoOffset(origRVA, nt, dll));
            while (orig->u1.AddressOfData)
            {
                FARPROC proc = nullptr;
                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    proc = GetProcAddress(mod, reinterpret_cast<LPCSTR>(orig->u1.Ordinal & 0xFFFF));
                else
                {
                    auto ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(dll + RVAtoOffset(orig->u1.AddressOfData, nt, dll));
                    proc = GetProcAddress(mod, ibn->Name);
                }
                WriteMem(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + thunkRVA), &proc, sizeof(proc));
                thunkRVA += sizeof(uintptr_t);
                orig++;
            }
            impDesc++;
        }
    }

    uintptr_t entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA != 0)
    {
        FARPROC entryPoint = reinterpret_cast<FARPROC>(reinterpret_cast<uintptr_t>(remoteBase) + entryRVA);

        ManualMapStub localStub = { entryPoint, static_cast<HMODULE>(remoteBase) };

        LPVOID remoteStubData = VirtualAllocEx(hProcess, nullptr, sizeof(ManualMapStub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        LPVOID remoteStubCode = VirtualAllocEx(hProcess, nullptr, sizeof(stubCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(hProcess, remoteStubData, &localStub, sizeof(localStub), nullptr);
        WriteProcessMemory(hProcess, remoteStubCode, stubCode, sizeof(stubCode), nullptr);

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)remoteStubCode,
            remoteStubData,
            0,
            nullptr);

        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }


    return true;
}