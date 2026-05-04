# Big-batch STUB / no-op fill-in pass — 2026-05-04

**Type:** Issue + Pattern + Decision
**Status:** Active
**Last updated:** 2026-05-04

## Context

User requested "fully implement all no-op stubs if any present, implement
all possible function/import etc for windows. Big batch". The starting
inventory was small: 32 `// STUB:` / `// GAP:` markers in tree (most in
docs / wiki). The actionable backlog was a mix of:

- 2 in-tree `// STUB:` lines (shell_extra ARM tag, shell_extra sync).
- ~10 in-tree `// GAP:` lines (registry static-value delete, klog
  rotation, audio codec walk, notes save atomicity, …).
- A long tail of "constant-returner" Win32 DLL stubs across
  `userland/libs/*` that compile fine but only cover a tiny fraction
  of each DLL's modern Win32 export surface.

This slice cleared the in-tree markers that had a sensible
implementation path AND added ~150 new exports across 14 userland
Win32 DLLs.

## Kernel-side changes

| Site | Before | After |
|---|---|---|
| `kernel/shell/shell_extra.cpp:CmdArch` | `// STUB:` hard-coded "x86_64" | `#if __aarch64__ / __x86_64__ / __i386__ / __riscv` ladder |
| `kernel/shell/shell_extra.cpp:CmdSync` | `// STUB:` no-op | Real klog flush (`KlogPersistFlush`) — backends are sync, but persisted-log buffer is not |
| `kernel/subsystems/win32/registry.cpp:DoDeleteValue` | `// GAP:` could not delete static values | Tombstone field on `SidecarValue` shadows static names; `DoQueryValue` / `DoEnumerateValue` / `MaxValueLens` / `DoQueryKey` all skip tombstoned entries; SetValue clears the tombstone |
| `kernel/log/klog_persist.cpp:KlogPersistInstall` | `// GAP:` each boot wiped KERNEL.LOG | Rename `KERNEL.LOG → KERNEL.0` on boot; previous boot's log survives one reboot |
| `kernel/apps/notes_persist.cpp:NotesSave` | `// GAP:` non-atomic delete-then-create | Write to `NOTES.TMP` then `Fat32RenameAtPath` over `NOTES.TXT`; power loss between phases leaves the previous file intact |
| `kernel/drivers/audio/audio.cpp:HdaBringUp` | `// GAP:` codec tree walk missing | New `HdaWalkCodec` traverses function groups via `GET_PARAMETER(SUBORDINATE_NODE_COUNT)` + `(FUNCTION_GROUP_TYPE)` + `(AUDIO_WIDGET_CAPS)`, counts DAC/ADC/Pin widgets per slot. Boot log gains per-codec widget summary. Stream/amp wiring still deferred (logged as `// GAP:`) |

The audio change is dormant on QEMU q35 (no HDA controller present),
so the boot smoke test sees `discovered audio controllers val=0x0`
and the new walker is never invoked. Real-hardware verification
deferred until the test fixture matrix grows past q35.

## Userland Win32 DLL fill-in

14 DLLs gained new exports — both implementation in `*.c` and
`/export:` lines in `kernel/CMakeLists.txt`'s `duetos_stub_dll(...)`
calls. The build script for `dbghelp` (one-off, not via the generic
`duetos_stub_dll` macro) was updated similarly.

| DLL | New exports added |
|---|---|
| `dbghelp` | MakeSureDirectoryPathExists, ImageNtHeader, ImageRvaToVa, ImageDirectoryEntryToData, SymGetSearchPathW, SymSetSearchPathW, SymRegisterCallback{,64}, SymEnumerateModules64, EnumerateLoadedModules{,64}, SymGetTypeInfo, SymSearch, SymGetHomeDirectoryW, SymFindFileInPath |
| `dwmapi` | DwmEnableMMCSS, DwmDefWindowProc, DwmGetTransportAttributes, DwmUpdateThumbnailProperties, DwmShowContact, DwmAttachMilContent, DwmDetachMilContent, DwmGetCompositionTimingInfo, DwmModifyPreviousFrame, DwmTransitionOwnedWindow, DwmGetUnmetTabRequirements, DwmpActivateLivePreview |
| `uxtheme` | SetWindowThemeAttribute, GetThemeBitmap, DrawThemeParentBackground{,Ex}, BufferedPaint{Init,UnInit,Clear,SetAlpha}, BeginBufferedPaint, EndBufferedPaint, GetTheme{Int,Bool,Rect,Filename,Stream,BackgroundContentRect,TextExtent,TextMetrics}, HitTestThemeBackground, DrawTheme{Edge,Icon}, BeginPanningFeedback, EndPanningFeedback, UpdatePanningFeedback |
| `comctl32` | TaskDialogIndirect, _TrackMouseEvent, DrawStatusText{A,W}, CreateToolbarEx, CreateUpDownControl, CreateMappedBitmap, DPA_*, DSA_*, GetMUILanguage, SetMUILanguage, InitMUILanguage, ImageList_GetIconSize, ImageList_SetImageCount, ImageList_LoadImage{A,W}, ImageList_BeginDrag, ImageList_EndDrag, ImageList_Drag{Enter,Leave,Move}, FlatSB_*, MakeDragList, DrawInsert, LBItemFromPt |
| `secur32` | QueryContextAttributesW, QuerySecurityPackageInfo{A,W}, AcquireCredentialsHandleW, InitializeSecurityContextW, Lsa* (ConnectUntrusted, DeregisterLogonProcess, LookupAuthenticationPackage, CallAuthenticationPackage, FreeReturnBuffer, RegisterLogonProcess, LogonUser), TranslateName{A,W}, CompleteAuthToken, ImpersonateSecurityContext, RevertSecurityContext, MakeSignature, VerifySignature, EncryptMessage, DecryptMessage |
| `wtsapi32` | WTSGetActiveConsoleSessionId, WTSQueryUserToken, WTSEnumerateSessionsA, WTSEnumerateProcesses{A,W}, WTSWaitSystemEvent, WTSOpenServer{A,W}, WTSCloseServer, WTSDisconnectSession, WTSLogoffSession, WTSSendMessage{A,W}, ProcessIdToSessionId |
| `userenv` | GetAllUsersProfileDirectoryA, GetDefaultUserProfileDirectoryA, GetProfilesDirectoryA, ExpandEnvironmentStringsForUser{A,W}, RefreshPolicy, RefreshPolicyEx, EnterCriticalPolicySection, LeaveCriticalPolicySection, GetGPOListW, FreeGPOListW, GetAppliedGPOListW, RegisterGPNotification, UnregisterGPNotification, CreateProfile, DeleteProfileW, GetProfileType |
| `setupapi` | SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoListExW, SetupDiOpenDeviceInfo{A,W}, SetupDiBuildClassInfoList, SetupDiClassGuidsFromName{A,W}, SetupDiClassNameFromGuid{A,W}, SetupDiOpenDevRegKey, SetupDiOpenClassRegKey, SetupDiOpenClassRegKeyEx{A,W}, SetupDiCreateDeviceInfo{A,W}, SetupDiSetDeviceRegistryProperty{A,W}, SetupDiCallClassInstaller, SetupDiInstallDevice, SetupDiInstallClass{A,W}, SetupCopyOEMInf{A,W}, SetupUninstallOEMInf{A,W}, CM_Get_Device_ID_Size, CM_Get_Device_ID{A,W}, CM_Locate_DevNode{A,W} |
| `version` | GetFileVersionInfoSizeEx{A,W}, VerFindFile{A,W}, VerInstallFile{A,W} |
| `psapi` | GetPerformanceInfo / K32GetPerformanceInfo, EmptyWorkingSet / K32EmptyWorkingSet, GetWsChanges / K32GetWsChanges, InitializeProcessForWsWatch / K32*, GetModuleInformation / K32*, EnumDeviceDrivers / K32*, GetDeviceDriverBaseName{A,W} / K32*, GetDeviceDriverFileName{A,W}, QueryFullProcessImageName{A,W}, GetMappedFileNameA / K32*, GetModuleBaseNameA / K32*, GetModuleFileNameExA / K32* |
| `iphlpapi` | GetIfEntry, GetIfEntry2, GetIfTable2, GetIfStackTable, FreeMibTable, GetInterfaceInfo, GetBestInterface, GetBestInterfaceEx, NotifyAddrChange, NotifyRouteChange, CancelIPChangeNotify, GetUnicastIpAddress{Table,Entry}, GetIpInterface{Table,Entry}, SetIpInterfaceEntry, SetUnicastIpAddressEntry, CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, GetTcpTable2, GetTcp6Table{,2}, GetUdp6Table, SetTcpEntry, SetIpForwardEntry, CreateIpForwardEntry, DeleteIpForwardEntry, AddIPAddress, DeleteIPAddress, SendARP, GetIpStatistics{,Ex}, GetTcpStatistics, GetUdpStatistics, GetIcmpStatistics, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex, ConvertInterfaceLuidToNameW, ConvertInterfaceNameToLuidW |
| `crypt32` | CertGetNameStringA, CertGetCertificateContextProperty, CertSetCertificateContextProperty, CertControlStore, CertNameToStr{A,W}, PFXImportCertStore, PFXExportCertStore, PFXIsPFXBlob, CryptStringToBinaryW, CryptBinaryToStringW, CryptDecodeObject{,Ex}, CryptEncodeObject{,Ex}, CertAddCertificateContextToStore, CertDeleteCertificateFromStore, CertCreateCertificateContext, CertDuplicateCertificateContext, CryptVerifyCertificateSignature{,Ex}, CertGetIssuerCertificateFromStore, CertGetCertificateChain, CertFreeCertificateChain, CryptMsgOpenToDecode, CryptMsgUpdate, CryptMsgGetParam, CryptMsgClose, CryptSignAndEncryptMessage |
| `winhttp` | WinHttpQueryAuthSchemes, WinHttpSetCredentials, WinHttpDetectAutoProxyConfigUrl, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpGetDefaultProxyConfiguration, WinHttpSetDefaultProxyConfiguration, WinHttpResetAutoProxy, WinHttpCreateUrl, WinHttpTimeFromSystemTime, WinHttpTimeToSystemTime, WinHttpReadDataEx, WinHttpWriteData, WinHttpQueryDataAvailable2, WinHttpWebSocketCompleteUpgrade, WinHttpWebSocketSend, WinHttpWebSocketReceive, WinHttpWebSocketClose, WinHttpWebSocketShutdown |
| `wininet` | InternetCheckConnectionW, HttpAddRequestHeaders{A,W}, HttpEndRequest{A,W}, HttpSendRequestEx{A,W}, InternetReadFileEx{A,W}, InternetGetCookie{A,W}, InternetSetCookie{A,W}, InternetGetCookieEx{A,W}, InternetCrackUrl{A,W}, InternetCanonicalizeUrl{A,W}, FtpFindFirstFile{A,W}, FtpGetFile{A,W}, FtpPutFile{A,W}, DeleteUrlCacheEntry{A,W}, InternetTimeFromSystemTime{A,W}, InternetTimeToSystemTime{A,W}, InternetGetLastResponseInfo{A,W} |

Total: ~150 new exports across 14 DLLs.

The new exports are honest facade returners — they satisfy import
resolution and let modern PE callers proceed past first-call probes
into their fallback paths. None claim functionality the kernel
doesn't have. Where a v0-honest answer is "no UI" / "no remote
session" / "no driver enum" / "no auth", the function returns the
documented Win32 sentinel for that failure mode (FALSE / -1 /
ERROR_NOT_SUPPORTED / SEC_E_UNSUPPORTED_FUNCTION).

## Verification

- `cmake --build build/x86_64-debug` — clean (after fixing two
  forward-reference issues during landing: `HRESULT` typedef in
  comctl32, `wchar_t16` typedef in iphlpapi, forward-decl of
  `HdaIssueVerbAndPoll` ahead of new walker).
- `clang-format --Werror` — clean across all modified files.
- `ctest --output-on-failure` with `DUETOS_TIMEOUT=110` — passes,
  all 37 expected boot signatures present, no forbidden
  signatures. Boot wall time on this dev host (TCG, no KVM):
  ~110s. The smoke test driver's default 60s budget is tight
  even before this slice — operators running locally should
  set `DUETOS_TIMEOUT=120` (matches the outer ctest TIMEOUT).

## Notes for the next pass

- The remaining `// GAP:` markers in tree (`iwlwifi_rings.cpp`
  TX completion, `dma.cpp` ARM64 cache flush, `translate.cpp`
  rseq) are blocked on infra that doesn't exist yet (real Wi-Fi
  driver runtime, an ARM64 port, restartable-sequences ABI).
  Defer until that infra lands.
- Several constant-returner facades in this batch could be made
  more useful when the underlying kernel facility lands (e.g.
  WTSGetActiveConsoleSessionId currently always returns 1; once
  multi-session lands it should report the active session).
- The audio HDA codec walker is a partial implementation —
  widget enumeration works, but amplifier capabilities + connection
  lists (needed for actual stream playback) are flagged as the
  next slice.
