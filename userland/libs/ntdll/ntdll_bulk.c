#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * Bulk-generated NT thunks — completes the Bedrock Win-XP→Win11 NT
 * call coverage. Each thunk returns STATUS_NOT_IMPLEMENTED
 * (0xC0000002). The x64 calling convention places caller args in
 * RCX/RDX/R8/R9/stack; we ignore them and only set RAX.
 *
 * Architectural rule (wiki/kernel/Subsystem-Isolation.md):
 * Win32 is a façade for executing PE binaries — NotImpl thunks
 * satisfy malware-shape probes without offering any real DuetOS
 * effect. Real implementations replace each stub when the
 * underlying engine lands kernel-side. Until then, the explicit
 * NotImpl is more honest than the catch-all kSysNtNotImpl.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAccessCheckAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByType(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultList(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireCMFViewOwnership(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireCrossVmMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireProcessActivityReference(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddAtomEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAdjustTokenClaimsAndDeviceGroups(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertMultipleThreadByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertThreadByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertThreadByThreadIdEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateLocallyUniqueId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateReserveObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateUserPhysicalPagesEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateVirtualMemoryEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcAcceptConnectPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCancelMessage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcConnectPortEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreatePortSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateResourceReserve(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateSectionView(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeletePortSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteResourceReserve(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteSectionView(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDisconnectPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcImpersonateClientContainerOfPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcImpersonateClientOfPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcOpenSenderProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcOpenSenderThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcQueryInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcQueryInformationMessage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcRevokeSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcSetInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtApphelpCacheControl(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAssociateWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCallEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelDeviceWakeupRequest(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtChangeProcessState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtChangeThreadState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtClearAllSavepointsTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtClearSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCloseObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompactKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareObjects(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareSigningLevels(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareTokens(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompressKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtContinueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCopyFileChunk(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCrossVmEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCrossVmMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateDirectoryObjectEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateIRTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateJobSet(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateKeyTransacted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateLowBoxToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePagingFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateProcessStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateProfileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateThreadStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTokenEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWaitablePort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWnfStateName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeletePrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteWnfStateName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDirectGraphicsCall(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDisableLastKnownGood(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDisplayString(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDrawText(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDuplicateObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnableLastKnownGood(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateBootEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateDriverEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateSystemEnvironmentValuesEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateTransactionObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtExtendSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFilterBootOption(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFilterTokenEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushBuffersFileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushInstallUILanguage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushProcessWriteBuffers(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushWriteBuffer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreeUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreezeRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreezeTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCachedSigningLevel(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCompleteWnfStateSubscription(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCurrentProcessorNumberEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetDevicePowerState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNextProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNextThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNlsSectionPtr(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNotificationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetPlugPlayEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeNlsFiles(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitiatePowerAction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtIsSystemResumeAutomatic(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtIsUILanguageComitted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtListTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadEnclaveData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadHotPatch(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey3(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLockProductActivationKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLockRegistryKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMakePermanentObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMakeTemporaryObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtManageHotPatch(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtManagePartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapCMFModule(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapUserPhysicalPagesScatter(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapViewOfSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMarshallTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtModifyBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtModifyDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeDirectoryFileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeMultipleKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeSession(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenJobObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenKeyTransacted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenKeyTransactedEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenPrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSession(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrePrepareComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrePrepareEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrepareComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrepareEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrivilegedServiceAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPropagationComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPropagationFailed(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPssCaptureVaSpaceBulk(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPullTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryAuxiliaryCounterFrequency(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryBootEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryBootOptions(void)
{
    return (NTSTATUS)0xC0000002;
}
/* NtQueryDirectoryFile — real implementation backed by SYS_DIR_NEXT.
 *
 * Real Windows packs many entries into the caller's buffer; v0
 * returns ONE entry per call (NextEntryOffset = 0). Callers loop
 * until STATUS_NO_MORE_FILES — same observable contract, just one
 * round-trip per entry. RestartScan = TRUE issues SYS_DIR_REWIND
 * before fetching.
 *
 * Supported FILE_INFORMATION_CLASS values:
 *   1 = FileDirectoryInformation        (header 64 bytes + name)
 *   2 = FileFullDirectoryInformation    (header 68 bytes + name)
 *   3 = FileBothDirectoryInformation    (header 94 bytes + name)
 *  12 = FileNamesInformation            (header 12 bytes + name)
 *
 * Other classes return STATUS_NOT_IMPLEMENTED. The 4 classes above
 * cover every common Windows enumerator (FindFirstFile fallback +
 * direct-NT malware probes).
 *
 * The kernel-side SYS_DIR_NEXT report carries name + attributes +
 * size only; timestamps + EaSize + ShortName fields are zero-filled
 * (v0 has no ctime/atime/mtime tracking). */
struct Win32DirEntryReport_t
{
    char name[64];
    unsigned int attributes;
    unsigned int _pad;
    unsigned long long size_bytes;
    unsigned char _reserved[16];
};

__declspec(dllexport) NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                    void* IoStatusBlock, void* FileInformation, ULONG Length,
                                                    ULONG FileInformationClass, BOOL ReturnSingleEntry, void* FileName,
                                                    BOOL RestartScan)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)ReturnSingleEntry;
    (void)FileName; /* glob filter not honoured; sub-GAP */
    if (FileInformation == (void*)0 || Length == 0)
        return NTSTATUS_INVALID_PARAMETER;
    /* Accept only the directory-handle range. Other handles
     * (regular files via NtCreateFile without FILE_DIRECTORY_FILE)
     * → STATUS_INVALID_HANDLE — Windows returns the same. */
    unsigned long long h = (unsigned long long)(long long)FileHandle;
    if (h < 0xA00 || h > 0xA07)
        return (NTSTATUS)0xC0000008ULL; /* STATUS_INVALID_HANDLE */
    if (RestartScan)
    {
        long long rv;
        __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)156), "D"((long long)h) : "memory");
        if (rv < 0)
            return (NTSTATUS)0xC0000008ULL;
    }
    struct Win32DirEntryReport_t r;
    long long got;
    __asm__ volatile("int $0x80" : "=a"(got) : "a"((long long)155), "D"((long long)h), "S"((long long)&r) : "memory");
    if (got < 0)
        return (NTSTATUS)0xC0000008ULL;
    if (got == 0)
        return (NTSTATUS)0x80000006ULL; /* STATUS_NO_MORE_FILES */

    /* Compute the byte length of the wide-char name we'll emit
     * (NUL is NOT counted in FileNameLength on Windows). */
    unsigned name_chars = 0;
    while (name_chars < 64 && r.name[name_chars] != '\0')
        ++name_chars;
    const unsigned name_bytes = name_chars * 2; /* UTF-16 */

    /* Emit per the requested class. Output a single record;
     * NextEntryOffset = 0 marks end-of-record. */
    unsigned char* out = (unsigned char*)FileInformation;
    unsigned needed = 0;
    if (FileInformationClass == 1) /* FileDirectoryInformation */
    {
        needed = 64 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL; /* STATUS_BUFFER_TOO_SMALL */
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;                                                   /* NextEntryOffset */
        u32p[1] = 0;                                                   /* FileIndex */
        u64p[1] = 0;                                                   /* CreationTime  */
        u64p[2] = 0;                                                   /* LastAccessTime */
        u64p[3] = 0;                                                   /* LastWriteTime  */
        u64p[4] = 0;                                                   /* ChangeTime */
        u64p[5] = r.size_bytes;                                        /* EndOfFile  */
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095); /* AllocationSize */
        u32p[14] = r.attributes;                                       /* FileAttributes */
        u32p[15] = name_bytes;                                         /* FileNameLength */
    }
    else if (FileInformationClass == 2) /* FileFullDirectoryInformation */
    {
        needed = 68 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;
        u32p[1] = 0;
        u64p[1] = 0;
        u64p[2] = 0;
        u64p[3] = 0;
        u64p[4] = 0;
        u64p[5] = r.size_bytes;
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095);
        u32p[14] = r.attributes;
        u32p[15] = name_bytes;
        u32p[16] = 0; /* EaSize */
    }
    else if (FileInformationClass == 3) /* FileBothDirectoryInformation */
    {
        needed = 94 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;
        u32p[1] = 0;
        u64p[1] = 0;
        u64p[2] = 0;
        u64p[3] = 0;
        u64p[4] = 0;
        u64p[5] = r.size_bytes;
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095);
        u32p[14] = r.attributes;
        u32p[15] = name_bytes;
        u32p[16] = 0; /* EaSize */
        out[68] = 0;  /* ShortNameLength (bytes) */
        out[69] = 0;  /* _pad */
        for (unsigned i = 0; i < 24; ++i)
            out[70 + i] = 0; /* ShortName[12] WCHARs */
    }
    else if (FileInformationClass == 12) /* FileNamesInformation */
    {
        needed = 12 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        u32p[0] = 0;          /* NextEntryOffset */
        u32p[1] = 0;          /* FileIndex */
        u32p[2] = name_bytes; /* FileNameLength */
    }
    else
    {
        return (NTSTATUS)0xC0000002ULL; /* STATUS_NOT_IMPLEMENTED for other classes */
    }

    /* Append the FileName as UTF-16 right after the class header. */
    unsigned name_off = (FileInformationClass == 1)   ? 64
                        : (FileInformationClass == 2) ? 68
                        : (FileInformationClass == 3) ? 94
                                                      : 12;
    unsigned short* wname = (unsigned short*)(out + name_off);
    for (unsigned i = 0; i < name_chars; ++i)
        wname[i] = (unsigned short)(unsigned char)r.name[i];

    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = needed;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                      void* ApcContext, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass, ULONG QueryFlags,
                                                      void* FileName)
{
    /* SL_RESTART_SCAN = 0x01 in QueryFlags. Forward as the
     * RestartScan bool to NtQueryDirectoryFile. */
    return NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
                                FileInformationClass, /*ReturnSingleEntry=*/(QueryFlags & 0x02) != 0, FileName,
                                /*RestartScan=*/(QueryFlags & 0x01) != 0);
}

__declspec(dllexport) NTSTATUS ZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                    void* IoStatusBlock, void* FileInformation, ULONG Length,
                                                    ULONG FileInformationClass, BOOL ReturnSingleEntry, void* FileName,
                                                    BOOL RestartScan)
{
    return NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
                                FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}
__declspec(dllexport) NTSTATUS NtQueryDriverEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationAtom(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationByName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryIoCompletion(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryIoRingCapabilities(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryLicenseValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryMultipleValueKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryOpenSubKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryOpenSubKeysEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryPortInformationProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryQuotaInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityAttributesToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityPolicy(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemEnvironmentValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemEnvironmentValueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemInformationEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryVolumeInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryWnfStateNameInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueueApcThreadEx2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadOnlyEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadRequestData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadVirtualMemoryEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRegisterProtocolAddressInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRegisterThreadTerminatePort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseCMFViewOwnership(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseWorkerFactoryWorker(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRenameKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRenameTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplaceKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplacePartitionUnit(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplyWaitReceivePortEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplyWaitReplyPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRequestDeviceWakeup(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRequestWakeupLatency(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRestoreKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRevertContainerImpersonation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollforwardTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveMergedKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSavepointComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSerializeBoot(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetBootEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetBootOptions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetCachedSigningLevel(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetCachedSigningLevel2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDebugFilterState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDefaultHardErrorPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDriverEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetEventBoostPriority(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetEventEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetHighWaitLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetIRTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationSymbolicLink(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationVirtualMemory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetIoCompletionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLdtEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLowWaitHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetQuotaInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSecurityObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemEnvironmentValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemEnvironmentValueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemPowerState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemTime(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetThreadExecutionState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetTimerEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetVolumeInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetWnfProcessNotificationEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtShutdownWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSinglePhaseReject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtStartTm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSubmitIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSubscribeWnfStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSystemDebugControl(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtTerminateEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtThawRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtThawTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtTranslateFilePath(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUmsThreadYield(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKey2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnmapViewOfSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnsubscribeWnfStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUpdateWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForAlertByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForMultipleObjects(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForMultipleObjects32(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForWnfNotifications(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForWorkViaWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWorkerFactoryWorkerReady(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWriteRequestData(void)
{
    return (NTSTATUS)0xC0000002;
}
