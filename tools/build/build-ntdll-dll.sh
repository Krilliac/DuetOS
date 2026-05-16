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
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

# ntdll.dll is split into per-domain translation units (see
# ntdll_internal.h). Compile each *.c to its own .obj and
# lld-link them all into one DLL.
SRC_FILES=(
    "${SRC_DIR}/ntdll.c"
    "${SRC_DIR}/ntdll_rtl.c"
    "${SRC_DIR}/ntdll_seh.c"
    "${SRC_DIR}/ntdll_reg.c"
    "${SRC_DIR}/ntdll_info.c"
    "${SRC_DIR}/ntdll_facades.c"
    "${SRC_DIR}/ntdll_token.c"
    "${SRC_DIR}/ntdll_bulk.c"
)

WORK_DIR="$(dirname "${OUT_HEADER}")/ntdll"
mkdir -p "${WORK_DIR}"
DLL="${WORK_DIR}/ntdll.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

OBJS=()
for src in "${SRC_FILES[@]}"; do
    obj="${WORK_DIR}/$(basename "${src}" .c).obj"
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
        "${src}" \
        -o "${obj}"
    OBJS+=("${obj}")
done

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
    /export:NtAccessCheckAndAuditAlarm \
    /export:NtAccessCheckByType \
    /export:NtAccessCheckByTypeAndAuditAlarm \
    /export:NtAccessCheckByTypeResultList \
    /export:NtAccessCheckByTypeResultListAndAuditAlarm \
    /export:NtAccessCheckByTypeResultListAndAuditAlarmByHandle \
    /export:NtAcquireCMFViewOwnership \
    /export:NtAcquireCrossVmMutant \
    /export:NtAcquireProcessActivityReference \
    /export:NtAddAtomEx \
    /export:NtAddBootEntry \
    /export:NtAddDriverEntry \
    /export:NtAdjustTokenClaimsAndDeviceGroups \
    /export:NtAlertMultipleThreadByThreadId \
    /export:NtAlertThreadByThreadId \
    /export:NtAlertThreadByThreadIdEx \
    /export:NtAllocateLocallyUniqueId \
    /export:NtAllocateReserveObject \
    /export:NtAllocateUserPhysicalPages \
    /export:NtAllocateUserPhysicalPagesEx \
    /export:NtAllocateVirtualMemoryEx \
    /export:NtAlpcAcceptConnectPort \
    /export:NtAlpcCancelMessage \
    /export:NtAlpcConnectPortEx \
    /export:NtAlpcCreatePortSection \
    /export:NtAlpcCreateResourceReserve \
    /export:NtAlpcCreateSectionView \
    /export:NtAlpcCreateSecurityContext \
    /export:NtAlpcDeletePortSection \
    /export:NtAlpcDeleteResourceReserve \
    /export:NtAlpcDeleteSectionView \
    /export:NtAlpcDeleteSecurityContext \
    /export:NtAlpcDisconnectPort \
    /export:NtAlpcImpersonateClientContainerOfPort \
    /export:NtAlpcImpersonateClientOfPort \
    /export:NtAlpcOpenSenderProcess \
    /export:NtAlpcOpenSenderThread \
    /export:NtAlpcQueryInformation \
    /export:NtAlpcQueryInformationMessage \
    /export:NtAlpcRevokeSecurityContext \
    /export:NtAlpcSetInformation \
    /export:NtApphelpCacheControl \
    /export:NtAssociateWaitCompletionPacket \
    /export:NtCallEnclave \
    /export:NtCancelDeviceWakeupRequest \
    /export:NtCancelTimer2 \
    /export:NtCancelWaitCompletionPacket \
    /export:NtChangeProcessState \
    /export:NtChangeThreadState \
    /export:NtClearAllSavepointsTransaction \
    /export:NtClearSavepointTransaction \
    /export:NtCloseObjectAuditAlarm \
    /export:NtCommitComplete \
    /export:NtCommitEnlistment \
    /export:NtCommitRegistryTransaction \
    /export:NtCompactKeys \
    /export:NtCompareObjects \
    /export:NtCompareSigningLevels \
    /export:NtCompareTokens \
    /export:NtCompressKey \
    /export:NtContinueEx \
    /export:NtConvertBetweenAuxiliaryCounterAndPerformanceCounter \
    /export:NtCopyFileChunk \
    /export:NtCreateCpuPartition \
    /export:NtCreateCrossVmEvent \
    /export:NtCreateCrossVmMutant \
    /export:NtCreateDirectoryObjectEx \
    /export:NtCreateEnclave \
    /export:NtCreateEnlistment \
    /export:NtCreateEventPair \
    /export:NtCreateIRTimer \
    /export:NtCreateIoRing \
    /export:NtCreateJobSet \
    /export:NtCreateKeyTransacted \
    /export:NtCreateLowBoxToken \
    /export:NtCreatePagingFile \
    /export:NtCreatePartition \
    /export:NtCreatePrivateNamespace \
    /export:NtCreateProcessStateChange \
    /export:NtCreateProfileEx \
    /export:NtCreateRegistryTransaction \
    /export:NtCreateResourceManager \
    /export:NtCreateSectionEx \
    /export:NtCreateSemaphore \
    /export:NtCreateThread \
    /export:NtCreateThreadStateChange \
    /export:NtCreateTimer2 \
    /export:NtCreateToken \
    /export:NtCreateTokenEx \
    /export:NtCreateTransactionManager \
    /export:NtCreateWaitCompletionPacket \
    /export:NtCreateWaitablePort \
    /export:NtCreateWnfStateName \
    /export:NtCreateWorkerFactory \
    /export:NtDeleteBootEntry \
    /export:NtDeleteDriverEntry \
    /export:NtDeleteObjectAuditAlarm \
    /export:NtDeletePrivateNamespace \
    /export:NtDeleteWnfStateData \
    /export:NtDeleteWnfStateName \
    /export:NtDirectGraphicsCall \
    /export:NtDisableLastKnownGood \
    /export:NtDisplayString \
    /export:NtDrawText \
    /export:NtDuplicateObject \
    /export:NtEnableLastKnownGood \
    /export:NtEnumerateBootEntries \
    /export:NtEnumerateDriverEntries \
    /export:NtEnumerateSystemEnvironmentValuesEx \
    /export:NtEnumerateTransactionObject \
    /export:NtExtendSection \
    /export:NtFilterBootOption \
    /export:NtFilterTokenEx \
    /export:NtFlushBuffersFileEx \
    /export:NtFlushInstallUILanguage \
    /export:NtFlushProcessWriteBuffers \
    /export:NtFlushWriteBuffer \
    /export:NtFreeUserPhysicalPages \
    /export:NtFreezeRegistry \
    /export:NtFreezeTransactions \
    /export:NtGetCachedSigningLevel \
    /export:NtGetCompleteWnfStateSubscription \
    /export:NtGetCurrentProcessorNumberEx \
    /export:NtGetDevicePowerState \
    /export:NtGetNextProcess \
    /export:NtGetNextThread \
    /export:NtGetNlsSectionPtr \
    /export:NtGetNotificationResourceManager \
    /export:NtGetPlugPlayEvent \
    /export:NtInitializeEnclave \
    /export:NtInitializeNlsFiles \
    /export:NtInitializeRegistry \
    /export:NtInitiatePowerAction \
    /export:NtIsSystemResumeAutomatic \
    /export:NtIsUILanguageComitted \
    /export:NtListTransactions \
    /export:NtLoadEnclaveData \
    /export:NtLoadHotPatch \
    /export:NtLoadKey \
    /export:NtLoadKey2 \
    /export:NtLoadKey3 \
    /export:NtLoadKeyEx \
    /export:NtLockProductActivationKeys \
    /export:NtLockRegistryKey \
    /export:NtMakePermanentObject \
    /export:NtMakeTemporaryObject \
    /export:NtManageHotPatch \
    /export:NtManagePartition \
    /export:NtMapCMFModule \
    /export:NtMapUserPhysicalPages \
    /export:NtMapUserPhysicalPagesScatter \
    /export:NtMapViewOfSectionEx \
    /export:NtMarshallTransaction \
    /export:NtModifyBootEntry \
    /export:NtModifyDriverEntry \
    /export:NtNotifyChangeDirectoryFileEx \
    /export:NtNotifyChangeKey \
    /export:NtNotifyChangeMultipleKeys \
    /export:NtNotifyChangeSession \
    /export:NtOpenCpuPartition \
    /export:NtOpenEnlistment \
    /export:NtOpenEventPair \
    /export:NtOpenJobObject \
    /export:NtOpenKeyTransacted \
    /export:NtOpenKeyTransactedEx \
    /export:NtOpenObjectAuditAlarm \
    /export:NtOpenPartition \
    /export:NtOpenPrivateNamespace \
    /export:NtOpenRegistryTransaction \
    /export:NtOpenResourceManager \
    /export:NtOpenSection \
    /export:NtOpenSemaphore \
    /export:NtOpenSession \
    /export:NtOpenTransactionManager \
    /export:NtPrePrepareComplete \
    /export:NtPrePrepareEnlistment \
    /export:NtPrepareComplete \
    /export:NtPrepareEnlistment \
    /export:NtPrivilegedServiceAuditAlarm \
    /export:NtPropagationComplete \
    /export:NtPropagationFailed \
    /export:NtPssCaptureVaSpaceBulk \
    /export:NtPullTransaction \
    /export:NtQueryAuxiliaryCounterFrequency \
    /export:NtQueryBootEntryOrder \
    /export:NtQueryBootOptions \
    /export:NtQueryDirectoryFile \
    /export:ZwQueryDirectoryFile \
    /export:NtQueryDirectoryFileEx \
    /export:NtQueryDriverEntryOrder \
    /export:NtQueryInformationAtom \
    /export:NtQueryInformationByName \
    /export:NtQueryInformationCpuPartition \
    /export:NtQueryInformationEnlistment \
    /export:NtQueryInformationPort \
    /export:NtQueryInformationResourceManager \
    /export:NtQueryInformationTransaction \
    /export:NtQueryInformationTransactionManager \
    /export:NtQueryInformationWorkerFactory \
    /export:NtQueryIoCompletion \
    /export:NtQueryIoRingCapabilities \
    /export:NtQueryLicenseValue \
    /export:NtQueryMultipleValueKey \
    /export:NtQueryMutant \
    /export:NtQueryOpenSubKeys \
    /export:NtQueryOpenSubKeysEx \
    /export:NtQueryPortInformationProcess \
    /export:NtQueryQuotaInformationFile \
    /export:NtQuerySection \
    /export:NtQuerySecurityAttributesToken \
    /export:NtQuerySecurityObject \
    /export:NtQuerySecurityPolicy \
    /export:NtQuerySemaphore \
    /export:NtQuerySystemEnvironmentValue \
    /export:NtQuerySystemEnvironmentValueEx \
    /export:NtQuerySystemInformationEx \
    /export:NtQueryTimer \
    /export:NtQueryVolumeInformationFile \
    /export:NtQueryWnfStateData \
    /export:NtQueryWnfStateNameInformation \
    /export:NtQueueApcThreadEx2 \
    /export:NtReadOnlyEnlistment \
    /export:NtReadRequestData \
    /export:NtReadVirtualMemoryEx \
    /export:NtRecoverEnlistment \
    /export:NtRecoverResourceManager \
    /export:NtRecoverTransactionManager \
    /export:NtRegisterProtocolAddressInformation \
    /export:NtRegisterThreadTerminatePort \
    /export:NtReleaseCMFViewOwnership \
    /export:NtReleaseSemaphore \
    /export:NtReleaseWorkerFactoryWorker \
    /export:NtRenameKey \
    /export:NtRenameTransactionManager \
    /export:NtReplaceKey \
    /export:NtReplacePartitionUnit \
    /export:NtReplyWaitReceivePortEx \
    /export:NtReplyWaitReplyPort \
    /export:NtRequestDeviceWakeup \
    /export:NtRequestWakeupLatency \
    /export:NtRestoreKey \
    /export:NtRevertContainerImpersonation \
    /export:NtRollbackComplete \
    /export:NtRollbackEnlistment \
    /export:NtRollbackRegistryTransaction \
    /export:NtRollbackSavepointTransaction \
    /export:NtRollforwardTransactionManager \
    /export:NtSaveKey \
    /export:NtSaveKeyEx \
    /export:NtSaveMergedKeys \
    /export:NtSavepointComplete \
    /export:NtSavepointTransaction \
    /export:NtSerializeBoot \
    /export:NtSetBootEntryOrder \
    /export:NtSetBootOptions \
    /export:NtSetCachedSigningLevel \
    /export:NtSetCachedSigningLevel2 \
    /export:NtSetDebugFilterState \
    /export:NtSetDefaultHardErrorPort \
    /export:NtSetDriverEntryOrder \
    /export:NtSetEventBoostPriority \
    /export:NtSetEventEx \
    /export:NtSetHighEventPair \
    /export:NtSetHighWaitLowEventPair \
    /export:NtSetIRTimer \
    /export:NtSetInformationCpuPartition \
    /export:NtSetInformationEnlistment \
    /export:NtSetInformationIoRing \
    /export:NtSetInformationKey \
    /export:NtSetInformationObject \
    /export:NtSetInformationResourceManager \
    /export:NtSetInformationSymbolicLink \
    /export:NtSetInformationTransaction \
    /export:NtSetInformationTransactionManager \
    /export:NtSetInformationVirtualMemory \
    /export:NtSetInformationWorkerFactory \
    /export:NtSetIoCompletionEx \
    /export:NtSetLdtEntries \
    /export:NtSetLowEventPair \
    /export:NtSetLowWaitHighEventPair \
    /export:NtSetQuotaInformationFile \
    /export:NtSetSecurityObject \
    /export:NtSetSystemEnvironmentValue \
    /export:NtSetSystemEnvironmentValueEx \
    /export:NtSetSystemPowerState \
    /export:NtSetSystemTime \
    /export:NtSetThreadExecutionState \
    /export:NtSetTimer2 \
    /export:NtSetTimerEx \
    /export:NtSetVolumeInformationFile \
    /export:NtSetWnfProcessNotificationEvent \
    /export:NtShutdownWorkerFactory \
    /export:NtSinglePhaseReject \
    /export:NtStartTm \
    /export:NtSubmitIoRing \
    /export:NtSubscribeWnfStateChange \
    /export:NtSystemDebugControl \
    /export:NtTerminateEnclave \
    /export:NtThawRegistry \
    /export:NtThawTransactions \
    /export:NtTranslateFilePath \
    /export:NtUmsThreadYield \
    /export:NtUnloadKey \
    /export:NtUnloadKey2 \
    /export:NtUnloadKeyEx \
    /export:NtUnmapViewOfSectionEx \
    /export:NtUnsubscribeWnfStateChange \
    /export:NtUpdateWnfStateData \
    /export:NtWaitForAlertByThreadId \
    /export:NtWaitForMultipleObjects \
    /export:NtWaitForMultipleObjects32 \
    /export:NtWaitForWnfNotifications \
    /export:NtWaitForWorkViaWorkerFactory \
    /export:NtWaitHighEventPair \
    /export:NtWaitLowEventPair \
    /export:NtWorkerFactoryWorkerReady \
    /export:NtWriteRequestData \
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
    /export:RtlComputeCrc32 \
    /export:RtlGenRandom \
    /export:RtlSecureZeroMemory \
    `# Pure-compute IPv4 helpers (parsing happens in-process)` \
    /export:RtlIpv4StringToAddressA \
    /export:RtlIpv4StringToAddressW \
    /export:RtlIpv4AddressToStringA \
    /export:RtlIpv4AddressToStringW \
    /out:"${DLL}" \
    "${OBJS[@]}" 2>&1 | grep -v "align specified without /driver"
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
