#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <wchar.h>
#include "shugo-map.h"

_Static_assert(sizeof(shugo_row) == sizeof(MIB_TCPROW_OWNER_PID), "TCP row layout");
typedef DWORD (WINAPI *tcp_table_fn)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
static tcp_table_fn original;
static PVOID *import_slot;
static SRWLOCK control_lock = SRWLOCK_INIT, cache_lock = SRWLOCK_INIT;
static LONG mapped_rows;
static ULONGLONG refreshed;
static uint32_t games[32], mirrors[32];
static size_t game_count, mirror_count;

static int is_engine_name(const WCHAR *name) {
    size_t len = wcslen(name);
    return len > 10 && !_wcsnicmp(name, L"AionWG", 6) && !_wcsicmp(name + len - 4, L".exe");
}

static void refresh_processes(void) {
    ULONGLONG now = GetTickCount64();
    if (refreshed && now - refreshed < 1000) return;
    refreshed = now;
    game_count = mirror_count = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};
    if (Process32FirstW(snapshot, &entry)) do {
        if (!_wcsicmp(entry.szExeFile, L"AION2.exe")) {
            if (game_count == 32) { game_count = mirror_count = 0; break; }
            games[game_count++] = entry.th32ProcessID;
        } else if (is_engine_name(entry.szExeFile)) {
            if (mirror_count == 32) { game_count = mirror_count = 0; break; }
            mirrors[mirror_count++] = entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
}

static DWORD WINAPI hooked_table(PVOID table, PDWORD size, BOOL order, ULONG family,
                                 TCP_TABLE_CLASS kind, ULONG reserved) {
    DWORD result = original(table, size, order, family, kind, reserved);
    if (result || !table || !size || family != AF_INET || kind != TCP_TABLE_OWNER_PID_ALL)
        return result;
    MIB_TCPTABLE_OWNER_PID *tcp = table;
    if (*size < sizeof(DWORD) || tcp->dwNumEntries > (*size - sizeof(DWORD)) / sizeof(shugo_row))
        return result;
    AcquireSRWLockExclusive(&cache_lock);
    refresh_processes();
    unsigned mapped = shugo_map_rows((shugo_row *)tcp->table, tcp->dwNumEntries,
                                    games, game_count, mirrors, mirror_count);
    ReleaseSRWLockExclusive(&cache_lock);
    InterlockedExchangeAdd(&mapped_rows, (LONG)mapped);
    return result;
}

static DWORD replace_import(PVOID expected, PVOID replacement) {
    DWORD protection, ignored;
    if (!VirtualProtect(import_slot, sizeof(*import_slot), PAGE_READWRITE, &protection))
        return GetLastError();
    PVOID previous = InterlockedCompareExchangePointer(import_slot, replacement, expected);
    VirtualProtect(import_slot, sizeof(*import_slot), protection, &ignored);
    return previous == expected ? ERROR_SUCCESS : ERROR_BUSY;
}

__declspec(dllexport) DWORD WINAPI AionWGCompatStart(PVOID unused) {
    (void)unused;
    WCHAR path[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!length || length == MAX_PATH) return ERROR_BAD_PATHNAME;
    WCHAR *name = wcsrchr(path, L'\\');
    if (_wcsicmp(name ? name + 1 : path, L"shugogg-companion.exe")) return ERROR_ACCESS_DENIED;
    AcquireSRWLockExclusive(&control_lock);
    DWORD result = ERROR_SUCCESS;
    if (import_slot) goto done;
    HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll");
    if (!iphlp) { result = ERROR_MOD_NOT_FOUND; goto done; }
    original = (tcp_table_fn)(void *)GetProcAddress(iphlp, "GetExtendedTcpTable");
    if (!original) { result = ERROR_PROC_NOT_FOUND; goto done; }
    BYTE *base = (BYTE *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) { result = ERROR_PROC_NOT_FOUND; goto done; }
    IMAGE_IMPORT_DESCRIPTOR *descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva);
    for (; descriptor->Name; ++descriptor) {
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + descriptor->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            if ((PVOID)thunk->u1.Function != (PVOID)original) continue;
            import_slot = (PVOID *)&thunk->u1.Function;
            result = replace_import((PVOID)original, (PVOID)hooked_table);
            if (result) import_slot = NULL;
            goto done;
        }
    }
    result = ERROR_PROC_NOT_FOUND;
done:
    ReleaseSRWLockExclusive(&control_lock);
    return result;
}

__declspec(dllexport) DWORD WINAPI AionWGCompatStop(PVOID unused) {
    (void)unused;
    AcquireSRWLockExclusive(&control_lock);
    DWORD result = ERROR_SUCCESS;
    if (import_slot) {
        result = replace_import((PVOID)hooked_table, (PVOID)original);
        if (!result) import_slot = NULL;
    }
    ReleaseSRWLockExclusive(&control_lock);
    return result;
}

__declspec(dllexport) DWORD WINAPI AionWGCompatStatus(PVOID unused) {
    (void)unused;
    return (DWORD)InterlockedCompareExchange(&mapped_rows, 0, 0);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
