#!/usr/bin/env bash
# tools/build/build-ntdll-dll.sh
#
# Compiles userland/libs/ntdll/ntdll.c into a freestanding
# x86_64 Windows PE DLL. Retires the prior ntdll.dll flat
# stubs (Nt* / Zw* / Rtl* / Ldr* / __chkstk).
#
# Zw* aliases are emitted as same-DLL forwarders via
# /export:Zw=Nt lld-link flags — one copy of each function
# exported under both names.
#
# Usage:
#     build-ntdll-dll.sh <repo_root> <out_header>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/ntdll"
SRC_C="${SRC_DIR}/ntdll.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/ntdll"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/ntdll.obj"
DLL="${WORK_DIR}/ntdll.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -fno-builtin-memset \
    -fno-builtin-memcpy \
    -fno-builtin-memmove \
    -mno-red-zone \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${DLL}"

# Exports. Real implementations list both Nt* and Zw* (Zw == Nt
# in user mode). STATUS_NOT_IMPLEMENTED sinks for the rest.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10060000 \
    /export:__chkstk \
    /export:NtReturnNotImpl \
    `# Real Nt* / Zw* primitives` \
    /export:NtClose \
    /export:ZwClose=NtClose \
    /export:NtYieldExecution \
    /export:ZwYieldExecution=NtYieldExecution \
    /export:NtDelayExecution \
    /export:ZwDelayExecution=NtDelayExecution \
    /export:NtQueryPerformanceCounter \
    /export:ZwQueryPerformanceCounter=NtQueryPerformanceCounter \
    /export:NtQuerySystemTime \
    /export:ZwQuerySystemTime=NtQuerySystemTime \
    /export:NtTerminateProcess \
    /export:ZwTerminateProcess=NtTerminateProcess \
    /export:NtTerminateThread \
    /export:ZwTerminateThread=NtTerminateThread \
    `# Real cross-task thread control — back SYS_THREAD_SUSPEND/RESUME.` \
    `# v0 only accepts caller-local thread handles; cross-process thread` \
    `# suspend lands with NtOpenThread.` \
    /export:NtSuspendThread \
    /export:ZwSuspendThread=NtSuspendThread \
    /export:NtResumeThread \
    /export:ZwResumeThread=NtResumeThread \
    /export:NtAlertResumeThread \
    /export:ZwAlertResumeThread=NtAlertResumeThread \
    /export:NtGetContextThread \
    /export:ZwGetContextThread=NtGetContextThread \
    /export:NtSetContextThread \
    /export:ZwSetContextThread=NtSetContextThread \
    /export:NtOpenThread \
    /export:ZwOpenThread=NtOpenThread \
    /export:NtCreateSection \
    /export:ZwCreateSection=NtCreateSection \
    /export:NtMapViewOfSection \
    /export:ZwMapViewOfSection=NtMapViewOfSection \
    /export:NtUnmapViewOfSection \
    /export:ZwUnmapViewOfSection=NtUnmapViewOfSection \
    /export:NtDeleteFile \
    /export:ZwDeleteFile=NtDeleteFile \
    /export:NtSetValueKey \
    /export:ZwSetValueKey=NtSetValueKey \
    /export:NtDeleteValueKey \
    /export:ZwDeleteValueKey=NtDeleteValueKey \
    /export:NtFlushKey \
    /export:ZwFlushKey=NtFlushKey \
    /export:NtEnumerateValueKey \
    /export:ZwEnumerateValueKey=NtEnumerateValueKey \
    /export:NtQueryKey \
    /export:ZwQueryKey=NtQueryKey \
    /export:NtCreateKey \
    /export:NtDeleteKey \
    /export:NtEnumerateKey \
    /export:NtQueryInformationProcess \
    /export:ZwQueryInformationProcess=NtQueryInformationProcess \
    /export:ZwAllocateVirtualMemory=NtAllocateVirtualMemory \
    /export:ZwFreeVirtualMemory=NtFreeVirtualMemory \
    /export:NtProtectVirtualMemory \
    /export:ZwProtectVirtualMemory=NtProtectVirtualMemory \
    /export:NtCreateThreadEx \
    /export:ZwCreateThreadEx=NtCreateThreadEx \
    /export:NtCreateMutant \
    /export:ZwCreateMutant=NtCreateMutant \
    /export:NtOpenMutant \
    /export:ZwOpenMutant=NtOpenMutant \
    /export:NtCreateEvent \
    /export:ZwCreateEvent=NtCreateEvent \
    /export:NtOpenEvent \
    /export:ZwOpenEvent=NtOpenEvent \
    /export:NtQueryObject \
    /export:ZwQueryObject=NtQueryObject \
    /export:NtOpenProcessToken \
    /export:ZwOpenProcessToken=NtOpenProcessToken \
    /export:NtOpenProcessTokenEx \
    /export:ZwOpenProcessTokenEx=NtOpenProcessTokenEx \
    /export:NtOpenThreadToken \
    /export:ZwOpenThreadToken=NtOpenThreadToken \
    /export:NtOpenThreadTokenEx \
    /export:ZwOpenThreadTokenEx=NtOpenThreadTokenEx \
    /export:NtQueryInformationToken \
    /export:ZwQueryInformationToken=NtQueryInformationToken \
    /export:NtAdjustPrivilegesToken \
    /export:ZwAdjustPrivilegesToken=NtAdjustPrivilegesToken \
    /export:NtQueryAttributesFile \
    /export:ZwQueryAttributesFile=NtQueryAttributesFile \
    /export:NtQueryFullAttributesFile \
    /export:ZwQueryFullAttributesFile=NtQueryFullAttributesFile \
    /export:NtCreateFile \
    /export:ZwCreateFile=NtCreateFile \
    /export:NtOpenFile \
    /export:ZwOpenFile=NtOpenFile \
    /export:NtReadFile \
    /export:ZwReadFile=NtReadFile \
    /export:NtWriteFile \
    /export:ZwWriteFile=NtWriteFile \
    /export:NtQueryInformationFile \
    /export:ZwQueryInformationFile=NtQueryInformationFile \
    /export:NtSetInformationFile \
    /export:ZwSetInformationFile=NtSetInformationFile \
    /export:NtFlushBuffersFile \
    /export:ZwFlushBuffersFile=NtFlushBuffersFile \
    /export:NtFsControlFile \
    /export:ZwFsControlFile=NtFsControlFile \
    /export:NtDeviceIoControlFile \
    /export:ZwDeviceIoControlFile=NtDeviceIoControlFile \
    /export:NtCreateDebugObject \
    /export:ZwCreateDebugObject=NtCreateDebugObject \
    /export:NtDebugActiveProcess \
    /export:ZwDebugActiveProcess=NtDebugActiveProcess \
    /export:NtDebugContinue \
    /export:ZwDebugContinue=NtDebugContinue \
    /export:NtWaitForDebugEvent \
    /export:ZwWaitForDebugEvent=NtWaitForDebugEvent \
    /export:NtRemoveProcessDebug \
    /export:ZwRemoveProcessDebug=NtRemoveProcessDebug \
    /export:NtSetInformationDebugObject \
    /export:ZwSetInformationDebugObject=NtSetInformationDebugObject \
    /export:NtQueryDebugFilterState \
    /export:NtCreateJobObject \
    /export:ZwCreateJobObject=NtCreateJobObject \
    /export:NtAssignProcessToJobObject \
    /export:ZwAssignProcessToJobObject=NtAssignProcessToJobObject \
    /export:NtQueryInformationJobObject \
    /export:ZwQueryInformationJobObject=NtQueryInformationJobObject \
    /export:NtSetInformationJobObject \
    /export:ZwSetInformationJobObject=NtSetInformationJobObject \
    /export:NtTerminateJobObject \
    /export:ZwTerminateJobObject=NtTerminateJobObject \
    /export:NtIsProcessInJob \
    /export:ZwIsProcessInJob=NtIsProcessInJob \
    /export:NtQuerySystemTime \
    /export:ZwQuerySystemTime=NtQuerySystemTime \
    /export:NtQueryPerformanceCounter \
    /export:ZwQueryPerformanceCounter=NtQueryPerformanceCounter \
    /export:NtQuerySystemInformation \
    /export:ZwQuerySystemInformation=NtQuerySystemInformation \
    /export:NtSetSystemInformation \
    /export:ZwSetSystemInformation=NtSetSystemInformation \
    /export:NtCreatePort \
    /export:NtConnectPort \
    /export:NtListenPort \
    /export:NtAcceptConnectPort \
    /export:NtCompleteConnectPort \
    /export:NtRequestPort \
    /export:NtRequestWaitReplyPort \
    /export:NtReplyPort \
    /export:NtReplyWaitReceivePort \
    /export:NtAlpcCreatePort \
    /export:NtAlpcConnectPort \
    /export:NtAlpcSendWaitReceivePort \
    /export:NtAddAtom \
    /export:NtFindAtom \
    /export:NtDeleteAtom \
    /export:NtCreateSymbolicLinkObject \
    /export:NtOpenSymbolicLinkObject \
    /export:NtQuerySymbolicLinkObject \
    /export:NtCreateDirectoryObject \
    /export:NtOpenDirectoryObject \
    /export:NtQueryDirectoryObject \
    /export:NtLockFile \
    /export:NtUnlockFile \
    /export:NtQueryEaFile \
    /export:NtSetEaFile \
    /export:NtNotifyChangeDirectoryFile \
    /export:NtCancelIoFile \
    /export:NtCreateProcess \
    /export:ZwCreateProcess=NtCreateProcess \
    /export:NtCreateProcessEx \
    /export:ZwCreateProcessEx=NtCreateProcessEx \
    /export:NtCreateUserProcess \
    /export:ZwCreateUserProcess=NtCreateUserProcess \
    /export:NtSuspendProcess \
    /export:NtResumeProcess \
    /export:NtAccessCheck \
    /export:NtPrivilegeCheck \
    /export:NtImpersonateThread \
    /export:NtImpersonateAnonymousToken \
    /export:NtSetInformationThread \
    /export:ZwSetInformationThread=NtSetInformationThread \
    /export:NtQueryInformationThread \
    /export:ZwQueryInformationThread=NtQueryInformationThread \
    /export:NtSetInformationProcess \
    /export:ZwSetInformationProcess=NtSetInformationProcess \
    /export:NtCreateKeyedEvent \
    /export:NtOpenKeyedEvent \
    /export:NtWaitForKeyedEvent \
    /export:NtReleaseKeyedEvent \
    /export:NtCreateTimer \
    /export:NtSetTimer \
    /export:NtCancelTimer \
    /export:NtOpenTimer \
    /export:NtCreateIoCompletion \
    /export:NtOpenIoCompletion \
    /export:NtSetIoCompletion \
    /export:NtRemoveIoCompletion \
    /export:NtRemoveIoCompletionEx \
    /export:NtCreateTransaction \
    /export:NtCommitTransaction \
    /export:NtRollbackTransaction \
    /export:NtOpenTransaction \
    /export:NtFlushInstructionCache \
    /export:NtTestAlert \
    /export:NtRaiseException \
    /export:NtPulseEvent \
    /export:NtClearEvent \
    /export:NtQueryEvent \
    /export:NtSignalAndWaitForSingleObject \
    /export:NtQueueApcThread \
    /export:NtQueueApcThreadEx \
    /export:NtAlertThread \
    /export:NtCallbackReturn \
    /export:NtAdjustGroupsToken \
    /export:NtSetInformationToken \
    /export:NtCheckTokenMembership \
    /export:NtPrivilegeObjectAuditAlarm \
    /export:NtFlushVirtualMemory \
    /export:NtLockVirtualMemory \
    /export:NtUnlockVirtualMemory \
    /export:NtAreMappedFilesTheSame \
    /export:NtLoadDriver \
    /export:NtUnloadDriver \
    /export:NtShutdownSystem \
    /export:NtRaiseHardError \
    /export:NtSetTimerResolution \
    /export:NtQueryTimerResolution \
    /export:NtGetCurrentProcessorNumber \
    /export:NtCreateMailslotFile \
    /export:NtCreateNamedPipeFile \
    /export:NtImpersonateClientOfPort \
    /export:NtPowerInformation \
    /export:NtGetWriteWatch \
    /export:NtResetWriteWatch \
    /export:NtCreateProfile \
    /export:NtStartProfile \
    /export:NtStopProfile \
    /export:NtSetIntervalProfile \
    /export:NtQueryIntervalProfile \
    /export:NtPlugPlayControl \
    /export:NtVdmControl \
    /export:NtCancelIoFileEx \
    /export:NtCancelSynchronousIoFile \
    /export:NtReadFileScatter \
    /export:NtWriteFileGather \
    /export:NtTraceEvent \
    /export:NtTraceControl \
    /export:NtGetMUIRegistryInfo \
    /export:NtQueryDefaultLocale \
    /export:NtSetDefaultLocale \
    /export:NtQueryDefaultUILanguage \
    /export:NtSetDefaultUILanguage \
    /export:NtQueryInstallUILanguage \
    /export:NtSetUuidSeed \
    /export:NtAllocateUuids \
    /export:NtSecureConnectPort \
    /export:NtDuplicateToken \
    /export:NtFilterToken \
    /export:NtContinue \
    /export:ZwContinue=NtContinue \
    /export:NtAllocateVirtualMemory \
    /export:ZwAllocateVirtualMemory=NtAllocateVirtualMemory \
    /export:NtFreeVirtualMemory \
    /export:ZwFreeVirtualMemory=NtFreeVirtualMemory \
    /export:NtSetEvent \
    /export:ZwSetEvent=NtSetEvent \
    /export:NtResetEvent \
    /export:ZwResetEvent=NtResetEvent \
    /export:NtReleaseMutant \
    /export:ZwReleaseMutant=NtReleaseMutant \
    /export:NtWaitForSingleObject \
    /export:ZwWaitForSingleObject=NtWaitForSingleObject \
    `# STATUS_NOT_IMPLEMENTED aliases — route every unimplemented Nt* here` \
    /export:NtCreateFile=NtReturnNotImpl \
    /export:ZwCreateFile=NtReturnNotImpl \
    /export:NtOpenFile=NtReturnNotImpl \
    /export:ZwOpenFile=NtReturnNotImpl \
    /export:NtReadFile=NtReturnNotImpl \
    /export:ZwReadFile=NtReturnNotImpl \
    /export:NtWriteFile=NtReturnNotImpl \
    /export:ZwWriteFile=NtReturnNotImpl \
    /export:NtDeviceIoControlFile=NtReturnNotImpl \
    /export:ZwDeviceIoControlFile=NtReturnNotImpl \
    /export:NtQueryInformationFile=NtReturnNotImpl \
    /export:ZwQueryInformationFile=NtReturnNotImpl \
    /export:NtSetInformationFile=NtReturnNotImpl \
    /export:ZwSetInformationFile=NtReturnNotImpl \
    /export:NtQueryVolumeInformationFile=NtReturnNotImpl \
    /export:ZwQueryVolumeInformationFile=NtReturnNotImpl \
    /export:NtProtectVirtualMemory=NtReturnNotImpl \
    /export:ZwProtectVirtualMemory=NtReturnNotImpl \
    `# Real cross-process VM read/write/query — back SYS_PROCESS_VM_*.` \
    `# Together with NtOpenProcess they form the v0 cross-AS VM` \
    `# triad: open a handle, then read/write/query inside that target's` \
    `# address space without ever leaving the syscall surface.` \
    /export:NtReadVirtualMemory \
    /export:ZwReadVirtualMemory=NtReadVirtualMemory \
    /export:NtWriteVirtualMemory \
    /export:ZwWriteVirtualMemory=NtWriteVirtualMemory \
    /export:NtQueryVirtualMemory \
    /export:ZwQueryVirtualMemory=NtQueryVirtualMemory \
    /export:NtCreateEvent=NtReturnNotImpl \
    /export:ZwCreateEvent=NtReturnNotImpl \
    /export:NtCreateMutant=NtReturnNotImpl \
    /export:ZwCreateMutant=NtReturnNotImpl \
    /export:NtCreateSection=NtReturnNotImpl \
    /export:ZwCreateSection=NtReturnNotImpl \
    /export:NtMapViewOfSection=NtReturnNotImpl \
    /export:ZwMapViewOfSection=NtReturnNotImpl \
    /export:NtUnmapViewOfSection=NtReturnNotImpl \
    /export:ZwUnmapViewOfSection=NtReturnNotImpl \
    /export:NtWaitForMultipleObjects=NtReturnNotImpl \
    /export:ZwWaitForMultipleObjects=NtReturnNotImpl \
    /export:NtOpenProcess \
    /export:ZwOpenProcess=NtOpenProcess \
    /export:NtQueryInformationProcess=NtReturnNotImpl \
    /export:ZwQueryInformationProcess=NtReturnNotImpl \
    /export:NtSetInformationProcess=NtReturnNotImpl \
    /export:ZwSetInformationProcess=NtReturnNotImpl \
    /export:NtQueryInformationThread=NtReturnNotImpl \
    /export:ZwQueryInformationThread=NtReturnNotImpl \
    /export:NtSetInformationThread=NtReturnNotImpl \
    /export:ZwSetInformationThread=NtReturnNotImpl \
    /export:NtQuerySystemInformation=NtReturnNotImpl \
    /export:ZwQuerySystemInformation=NtReturnNotImpl \
    `# Real registry-read primitives — back SYS_REGISTRY (op-multiplexed).` \
    `# NtOpenKey + NtOpenKeyEx + NtQueryValueKey live here as real C` \
    `# functions; NtCreateKey / NtEnumerateKey / NtQueryKey stay NotImpl` \
    `# (registry is read-only in v0; subkey-children walker not implemented).` \
    /export:NtOpenKey \
    /export:ZwOpenKey=NtOpenKey \
    /export:NtOpenKeyEx \
    /export:ZwOpenKeyEx=NtOpenKeyEx \
    /export:NtQueryValueKey \
    /export:ZwQueryValueKey=NtQueryValueKey \
    /export:NtEnumerateKey=NtReturnNotImpl \
    /export:ZwEnumerateKey=NtReturnNotImpl \
    /export:NtQueryKey=NtReturnNotImpl \
    /export:ZwQueryKey=NtReturnNotImpl \
    /export:NtEnumerateValueKey=NtReturnNotImpl \
    /export:ZwEnumerateValueKey=NtReturnNotImpl \
    /export:LdrGetDllHandle=NtReturnNotImpl \
    /export:LdrGetProcedureAddress=NtReturnNotImpl \
    /export:LdrLoadDll=NtReturnNotImpl \
    `# Rtl* surface` \
    /export:RtlGetLastWin32Error \
    /export:RtlSetLastWin32Error \
    /export:RtlNtStatusToDosError \
    /export:RtlAllocateHeap \
    /export:RtlFreeHeap \
    /export:RtlSizeHeap \
    /export:RtlReAllocateHeap \
    /export:RtlCreateHeap \
    /export:RtlDestroyHeap \
    /export:RtlZeroMemory \
    /export:RtlFillMemory \
    /export:RtlCopyMemory \
    /export:RtlMoveMemory \
    /export:RtlCompareMemory \
    /export:RtlInitUnicodeString \
    /export:RtlInitAnsiString \
    /export:RtlFreeUnicodeString \
    /export:RtlInitializeCriticalSection \
    /export:RtlDeleteCriticalSection \
    /export:RtlEnterCriticalSection \
    /export:RtlLeaveCriticalSection \
    /export:RtlTryEnterCriticalSection \
    /export:RtlRunOnceExecuteOnce \
    /export:RtlLookupFunctionEntry \
    /export:RtlVirtualUnwind \
    /export:RtlCaptureContext \
    /export:RtlCaptureStackBackTrace \
    /export:RtlUnwind \
    /export:RtlUnwindEx \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-ntdll-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-ntdll-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinNtdllDllBytes \
    --namespace "duetos::fs::generated"

echo "build-ntdll-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
