#!/usr/bin/env bash
# tools/build-kernel32-dll.sh
#
# Compiles userland/libs/kernel32/kernel32.c into a
# freestanding x86_64 Windows PE DLL (our own kernel32.dll)
# and embeds the bytes as a C++ constexpr u8 array for
# inclusion in the kernel.
#
# This is the first real retirement of a flat-stubs-page
# entry into a userland DLL: GetCurrentProcessId now lives
# in ring-3 code instead of the kernel-hosted stubs page.
# Future slices extend this DLL with additional exports; the
# corresponding kStubsTable entries become dead code (still
# compiled but never reached because the via-DLL path
# matches first).
#
# Usage:
#     build-kernel32-dll.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/kernel32"
SRC_C="${SRC_DIR}/kernel32.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/kernel32"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/kernel32.obj"
DLL="${WORK_DIR}/kernel32.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -mno-red-zone \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${DLL}"

# /base:0x10020000 — 1 MiB above customdll2.dll's 0x10010000.
# Headroom for kernel32 as it grows across future slices.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10020000 \
    /export:GetCurrentProcessId \
    /export:GetCurrentThreadId \
    /export:GetCurrentProcess \
    /export:GetCurrentThread \
    /export:GetLastError \
    /export:SetLastError \
    /export:ExitProcess \
    /export:TerminateProcess \
    /export:IsDebuggerPresent \
    /export:IsProcessorFeaturePresent \
    /export:SetConsoleCtrlHandler \
    /export:GetStdHandle \
    /export:Sleep \
    /export:SwitchToThread \
    /export:GetTickCount \
    /export:GetTickCount64 \
    /export:InterlockedIncrement \
    /export:InterlockedDecrement \
    /export:InterlockedExchange \
    /export:InterlockedCompareExchange \
    /export:InterlockedExchangeAdd \
    /export:InterlockedAnd \
    /export:InterlockedOr \
    /export:InterlockedXor \
    /export:InterlockedIncrement64 \
    /export:InterlockedDecrement64 \
    /export:InterlockedExchange64 \
    /export:InterlockedCompareExchange64 \
    /export:InterlockedExchangeAdd64 \
    /export:InterlockedAnd64 \
    /export:InterlockedOr64 \
    /export:InterlockedXor64 \
    /export:GetConsoleMode \
    /export:SetConsoleMode \
    /export:GetConsoleCP \
    /export:GetConsoleOutputCP \
    /export:SetConsoleOutputCP \
    /export:OutputDebugStringA \
    /export:OutputDebugStringW \
    /export:GetLogicalDrives \
    /export:GetDriveTypeA \
    /export:GetDriveTypeW \
    /export:IsWow64Process \
    /export:IsWow64Process2 \
    /export:GetModuleHandleExW \
    /export:GetModuleHandleExA \
    /export:FreeLibrary \
    /export:InterlockedPushEntrySList \
    /export:InterlockedPopEntrySList \
    /export:InterlockedFlushSList \
    /export:InitializeSListHead \
    /export:VirtualAlloc \
    /export:VirtualAllocEx \
    /export:VirtualFree \
    /export:VirtualFreeEx \
    /export:VirtualProtect \
    /export:VirtualProtectEx \
    /export:lstrlenA \
    /export:lstrcmpA \
    /export:lstrcmpiA \
    /export:lstrcpyA \
    /export:lstrlenW \
    /export:lstrcmpW \
    /export:lstrcmpiW \
    /export:lstrcpyW \
    /export:WriteFile \
    /export:WriteConsoleA \
    /export:WriteConsoleW \
    /export:CloseHandle \
    /export:CreateFileW \
    /export:ReadFile \
    /export:SetFilePointerEx \
    /export:GetFileSizeEx \
    /export:GetFileSize \
    /export:GetSystemTimeAsFileTime \
    /export:QueryPerformanceCounter \
    /export:QueryPerformanceFrequency \
    /export:GetProcessHeap \
    /export:HeapAlloc \
    /export:HeapFree \
    /export:HeapSize \
    /export:HeapReAlloc \
    /export:HeapCreate \
    /export:HeapDestroy \
    /export:GetACP \
    /export:GetOEMCP \
    /export:IsValidCodePage \
    /export:MultiByteToWideChar \
    /export:WideCharToMultiByte \
    /export:TlsAlloc \
    /export:TlsFree \
    /export:TlsGetValue \
    /export:TlsSetValue \
    /export:CreateMutexW \
    /export:CreateMutexA \
    /export:ReleaseMutex \
    /export:CreateEventW \
    /export:CreateEventA \
    /export:SetEvent \
    /export:ResetEvent \
    /export:CreateSemaphoreW \
    /export:CreateSemaphoreA \
    /export:ReleaseSemaphore \
    /export:WaitForSingleObject \
    /export:WaitForSingleObjectEx \
    /export:InitializeCriticalSection \
    /export:InitializeCriticalSectionEx \
    /export:InitializeCriticalSectionAndSpinCount \
    /export:DeleteCriticalSection \
    /export:EnterCriticalSection \
    /export:LeaveCriticalSection \
    /export:TryEnterCriticalSection \
    /export:InitializeSRWLock \
    /export:AcquireSRWLockExclusive \
    /export:ReleaseSRWLockExclusive \
    /export:TryAcquireSRWLockExclusive \
    /export:AcquireSRWLockShared \
    /export:ReleaseSRWLockShared \
    /export:TryAcquireSRWLockShared \
    /export:InitOnceExecuteOnce \
    /export:CreateThread \
    /export:ResumeThread \
    /export:GetExitCodeThread \
    /export:ExitThread \
    /export:GetExitCodeProcess \
    /export:FindFirstFileA /export:FindFirstFileW \
    /export:FindNextFileA /export:FindNextFileW /export:FindClose \
    /export:CopyFileA /export:CopyFileW \
    /export:MoveFileA /export:MoveFileW \
    /export:DeleteFileA /export:DeleteFileW \
    /export:GetFileAttributesA /export:GetFileAttributesW \
    /export:SetFileAttributesA /export:SetFileAttributesW \
    /export:CreateDirectoryA /export:CreateDirectoryW \
    /export:RemoveDirectoryA /export:RemoveDirectoryW \
    /export:FlushFileBuffers \
    /export:GetTempPathA /export:GetTempPathW \
    /export:GetWindowsDirectoryA /export:GetWindowsDirectoryW \
    /export:GetSystemDirectoryA /export:GetSystemDirectoryW \
    /export:GetSystemWindowsDirectoryW \
    /export:GetTempFileNameA /export:GetTempFileNameW \
    /export:GetCurrentDirectoryA \
    /export:SetCurrentDirectoryA /export:SetCurrentDirectoryW \
    /export:CreateToolhelp32Snapshot \
    /export:Process32FirstW /export:Process32NextW \
    /export:Process32First /export:Process32Next \
    /export:OpenProcess \
    /export:GenerateConsoleCtrlEvent \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-kernel32-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-kernel32-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinKernel32DllBytes \
    --namespace "duetos::fs::generated"

echo "build-kernel32-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
