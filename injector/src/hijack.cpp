#include <windows.h>
#include <vector>
#include <string>
#include "../log_handler.hpp"

#pragma comment(lib, "ntdll.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemHandleInformation 16

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtDuplicateObject_t        = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
using RtlAdjustPrivilege_t       = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
using NtQueryObject_t            = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct OBJECT_TYPE_INFORMATION_MINGW {
    UNICODE_STRING TypeName;
    WCHAR NameBuffer[260];
} OBJECT_TYPE_INFORMATION_MINGW;

static bool IsProcessHandle(HANDLE h, NtQueryObject_t NtQueryObject)
{
    BYTE buf[0x2000] = {};
    ULONG retLen = 0;

    if (!NT_SUCCESS(NtQueryObject(h, 2, buf, sizeof(buf), &retLen)))
        return false;

    auto* info = reinterpret_cast<OBJECT_TYPE_INFORMATION_MINGW*>(buf);
    std::wstring typeName(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
    return (typeName == L"Process");
}

HANDLE HijackProcessHandle(DWORD targetPid)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        LOG_ERROR("Failed to get ntdll.dll handle");
        return nullptr;
    }

    const auto NtQuerySystemInformation =
        reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto NtDuplicateObject =
        reinterpret_cast<NtDuplicateObject_t>(GetProcAddress(ntdll, "NtDuplicateObject"));
    const auto RtlAdjustPrivilege =
        reinterpret_cast<RtlAdjustPrivilege_t>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));
    const auto NtQueryObject =
        reinterpret_cast<NtQueryObject_t>(GetProcAddress(ntdll, "NtQueryObject"));

    if (!NtQuerySystemInformation || !NtDuplicateObject || !RtlAdjustPrivilege || !NtQueryObject) {
        LOG_ERROR("Failed to resolve ntdll exports");
        return nullptr;
    }

    BOOLEAN old = FALSE;
    RtlAdjustPrivilege(20, TRUE, FALSE, &old);

    ULONG size = 0x20000;
    std::vector<BYTE> buffer(size);

    for (;;) {
        NTSTATUS status = NtQuerySystemInformation(
            SystemHandleInformation,
            buffer.data(),
            size,
            &size
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(size);
            continue;
        }

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtQuerySystemInformation(SystemHandleInformation) failed");
            return nullptr;
        }

        break;
    }

    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.data());

    for (ULONG i = 0; i < info->NumberOfHandles; i++)
    {
        const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = info->Handles[i];

        HANDLE owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.UniqueProcessId);
        if (!owner)
            continue;

        HANDLE dup = nullptr;
        NTSTATUS dupSt = NtDuplicateObject(
            owner,
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(h.HandleValue)),
            GetCurrentProcess(),
            &dup,
            PROCESS_ALL_ACCESS,
            0,
            0
        );

        CloseHandle(owner);

        if (!NT_SUCCESS(dupSt) || !dup)
            continue;

        if (!IsProcessHandle(dup, NtQueryObject)) {
            CloseHandle(dup);
            continue;
        }

        DWORD pointedPid = GetProcessId(dup);

        if (pointedPid == targetPid)
        {
            LOG_SUCCESS(Log::to_string_stream(h.UniqueProcessId, " -> 0x", std::hex, static_cast<unsigned>(h.HandleValue)));
            return dup;
        }

        CloseHandle(dup);
    }

    LOG_ERROR(Log::to_string_stream(
        "Failed to find any process handle referencing PID ",
        targetPid
    ));

    return nullptr;
}
