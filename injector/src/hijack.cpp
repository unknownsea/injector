#include "../include/hijack.h"

#include <cstdio>
#include <windows.h>
#include <winternl.h>
#include <vector>

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef SeDebugPrivilege
#define SeDebugPrivilege 20
#endif

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtDuplicateObject_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

#pragma pack(push, 1)
struct LocalSystemHandleTableEntryInfoEx {
    PVOID      Object;
    ULONG_PTR  UniqueProcessId;
    HANDLE     HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
};
#pragma pack(pop)

HANDLE HijackProcessHandle(DWORD targetPid)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    auto NtDuplicateObject = reinterpret_cast<NtDuplicateObject_t>(
        GetProcAddress(ntdll, "NtDuplicateObject"));
    auto RtlAdjustPrivilege = reinterpret_cast<RtlAdjustPrivilege_t>(
        GetProcAddress(ntdll, "RtlAdjustPrivilege"));

    if (!NtQuerySystemInformation || !NtDuplicateObject || !RtlAdjustPrivilege)
        return NULL;

    BOOLEAN oldPriv = FALSE;
    RtlAdjustPrivilege(SeDebugPrivilege, TRUE, FALSE, &oldPriv);

    ULONG bufSize = 0x10000;
    std::vector<BYTE> buffer;
    buffer.resize(bufSize);

    NTSTATUS status = 0;
    while (true)
    {
        status = NtQuerySystemInformation(
            /*SystemInformationClass*/ 16, // SystemHandleInformation
            buffer.data(),
            bufSize,
            &bufSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(bufSize);
            continue;
        }

        if (!NT_SUCCESS(status)) {
            return NULL;
        }
        break;
    }

    if (buffer.size() < sizeof(ULONG_PTR) * 2)
        return NULL;

    ULONG_PTR numberOfHandles = *reinterpret_cast<ULONG_PTR*>(buffer.data());

    size_t entriesOffset = sizeof(ULONG_PTR) * 2;
    size_t entrySize = sizeof(LocalSystemHandleTableEntryInfoEx);

    // bounds check
    if (buffer.size() < entriesOffset + (entrySize * numberOfHandles))
        ;

    auto ProcessTypeIndex = 7;

    for (ULONG_PTR i = 0; i < numberOfHandles; ++i)
    {
        size_t offset = entriesOffset + (i * entrySize);
        if (offset + entrySize > buffer.size())
            break;

        LocalSystemHandleTableEntryInfoEx* entry =
            reinterpret_cast<LocalSystemHandleTableEntryInfoEx*>(buffer.data() + offset);

        if (entry->ObjectTypeIndex != ProcessTypeIndex)
            continue;

        DWORD ownerPid = static_cast<DWORD>(entry->UniqueProcessId & 0xFFFFFFFF);

        if (ownerPid == 0)
            continue;

        HANDLE ownerHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ownerPid);
        if (!ownerHandle)
            continue;

        HANDLE duplicated = NULL;
        NTSTATUS dupStatus = NtDuplicateObject(
            ownerHandle,
            entry->HandleValue,
            GetCurrentProcess(),
            &duplicated,
            PROCESS_ALL_ACCESS,
            0,
            0);

        CloseHandle(ownerHandle);

        if (!NT_SUCCESS(dupStatus) || !duplicated)
            continue;



        DWORD dupPid = GetProcessId(duplicated);
        // Successfully duplicated → handle is hijackable
        printf(
            "[HIJACKABLE] OwnerPID=%lu -> Handle=0x%X -> PointsToPID=%lu (Access=0x%X)\n",
            ownerPid,
            (unsigned int)(uintptr_t)entry->HandleValue,
            dupPid,
            entry->GrantedAccess
        );


        if (dupPid == targetPid) {
            return duplicated;
        }

        CloseHandle(duplicated);
    }

    return NULL;
}