# DuetOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.
#
# The embedded symbol table (used by the panic dump path to resolve RIPs to
# function/file/line) needs a two-stage build:
#
#   1. Link `duetos-kernel-stage1.elf` with a stub symbol table. Every
#      function / data symbol in this image already sits at its final VA
#      because the generated TU is pinned to the end of the kernel source
#      list — rodata growth in stage 2 happens strictly AFTER every other
#      symbol.
#
#   2. Run `tools/build/gen-symbols.sh` against stage 1 to produce
#      `symbols_generated.cpp`, a sorted `{addr, size, line, name, file}`
#      table, and relink the final `duetos-kernel.elf` with it in place
#      of the stub.
#
# The final image is what the ISO target packages. Stage 1 is a throwaway.

# ----------------------------------------------------------------------------
# Kernel source discovery — globbed dynamically.
#
# Every .cpp / .c / .S under kernel/ is part of the kernel image with two
# exceptions, both removed below:
#
#   - util/symbols_stub.cpp — stage-1 only. Stage 2 swaps in the generated
#     symbols table TU in this slot.
#   - tests/  — once present, hosted unit tests live here and are NOT linked
#     into the bare-metal kernel.
#
# CONFIGURE_DEPENDS reruns the glob when a file appears or disappears, so
# adding a new source file just needs the file itself; no CMakeLists edit.
# ----------------------------------------------------------------------------
file(GLOB_RECURSE DUETOS_KERNEL_SHARED_SOURCES
    CONFIGURE_DEPENDS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.S"
)

# Stage 1 owns this file exclusively; stage 2 substitutes the generated TU.
list(REMOVE_ITEM DUETOS_KERNEL_SHARED_SOURCES util/symbols_stub.cpp)

# Future-proofing: keep tests/ out of the kernel image if/when it appears.
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^tests/")

# security/stack_canary.cpp provides __stack_chk_fail and the
# RandomizeStackCanary helper. The latter updates the cookie at
# runtime; if ANY function in this file gets compiled with stack
# protection, the prologue/epilogue would sample __stack_chk_guard
# before/after the update and mismatch. The source uses
# __attribute__((no_stack_protector)) on the two functions that
# care; -fno-stack-protector on the whole TU is belt + braces.
set_source_files_properties(
    security/stack_canary.cpp
    PROPERTIES COMPILE_OPTIONS "-fno-stack-protector"
)

# ----------------------------------------------------------------------------
# Embedded-blob plumbing.
#
# The kernel image bakes in a handful of generated headers built from
# userland sources (PE fixtures + DLL stubs). Every entry shares the
# same shape: run a build script, write a generated header into the
# build dir, register the header as a kernel source so both stages
# pick it up.
#
# tools/build/embed-blob.py is the underlying byte-array emitter the
# build scripts call into. The duetos_embed_blob() helper wraps the
# add_custom_command + list-append pattern.
# ----------------------------------------------------------------------------
set(DUETOS_EMBED_BLOB_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build/embed-blob.py")

# Helper: register a generated header that the kernel image embeds.
#
#   duetos_embed_blob(header
#       SCRIPT  <path>            # build script invoked as: <script> SRCROOT <header>
#       SRC     <path>            # primary source the script reads
#       COMMENT <text>            # CMake progress message
#       [DEFS_DIR <path>]         # if set, glob *.def in this dir as deps
#       [EXTRA_DEPS dep1 ...])    # additional deps appended verbatim
#
# The output header lives at ${CMAKE_CURRENT_BINARY_DIR}/<header>.
function(duetos_embed_blob header_name)
    cmake_parse_arguments(EB
        ""                              # no boolean opts
        "SCRIPT;SRC;COMMENT;DEFS_DIR"   # single-value
        "EXTRA_DEPS"                    # multi-value
        ${ARGN})

    set(_header "${CMAKE_CURRENT_BINARY_DIR}/${header_name}")
    set(_defs "")
    if(EB_DEFS_DIR)
        file(GLOB _defs CONFIGURE_DEPENDS "${EB_DEFS_DIR}/*.def")
    endif()

    add_custom_command(
        OUTPUT  "${_header}"
        COMMAND "${EB_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${_header}"
        DEPENDS "${EB_SRC}" "${EB_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
                ${_defs} ${EB_EXTRA_DEPS}
        COMMENT "${EB_COMMENT}"
        VERBATIM
    )

    set(DUETOS_KERNEL_SHARED_SOURCES
        ${DUETOS_KERNEL_SHARED_SOURCES} "${_header}"
        PARENT_SCOPE)
endfunction()

# ----------------------------------------------------------------------------
# PE fixtures embedded into ramfs as /bin/*.exe.
# ----------------------------------------------------------------------------
duetos_embed_blob(generated_hello_pe.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-hello-pe.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/hello_pe/hello.c"
    COMMENT "Compiling + embedding /bin/hello.exe (freestanding PE)")

duetos_embed_blob(generated_hello_winapi.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-hello-winapi.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi"
    COMMENT  "Compiling + embedding /bin/hello_winapi.exe (Win32 import path)")

duetos_embed_blob(generated_thread_stress.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-thread-stress.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress"
    COMMENT  "Compiling + embedding /bin/thread_stress.exe (CreateThread path)")

duetos_embed_blob(generated_syscall_stress.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-syscall-stress.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress"
    COMMENT  "Compiling + embedding /bin/syscall_stress.exe (batch 51 API coverage)")

duetos_embed_blob(generated_windowed_hello.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-windowed-hello.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/windowed_hello/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/windowed_hello"
    COMMENT  "Compiling + embedding /bin/windowed_hello.exe (user32 window bridge)")

duetos_embed_blob(generated_customdll_test.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-customdll-test.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test"
    COMMENT  "Compiling + embedding /bin/customdll_test.exe (stage-2 slice 6 fixture)")

duetos_embed_blob(generated_reg_fopen_test.h
    SCRIPT   "${CMAKE_SOURCE_DIR}/tools/build/build-reg-fopen-test.sh"
    SRC      "${CMAKE_SOURCE_DIR}/userland/apps/reg_fopen_test/hello.c"
    DEFS_DIR "${CMAKE_SOURCE_DIR}/userland/apps/reg_fopen_test"
    COMMENT  "Compiling + embedding reg_fopen_test.exe (registry + fopen fixture)")

# ----------------------------------------------------------------------------
# Real Windows PE — windows-kill.exe (~80 KiB binary, 12 DLL deps).
# This one isn't compiled from source; it's a prebuilt MSVC PE we
# embed verbatim for the loader's diagnostic path. Custom command
# (not duetos_embed_blob) because it calls embed-blob.py directly
# with a custom symbol name + namespace.
# ----------------------------------------------------------------------------
set(DUETOS_WINKILL_SRC    "${CMAKE_SOURCE_DIR}/userland/apps/windows_kill/windows-kill.exe")
set(DUETOS_WINKILL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_winkill_pe.h")
add_custom_command(
    OUTPUT "${DUETOS_WINKILL_HEADER}"
    COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_WINKILL_SRC}" "${DUETOS_WINKILL_HEADER}"
            kBinWinKillBytes --namespace "duetos::fs::generated"
    DEPENDS "${DUETOS_WINKILL_SRC}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding real Windows PE /bin/windows-kill.exe"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_WINKILL_HEADER}")

# ----------------------------------------------------------------------------
# Userland DLLs embedded into the kernel image. Each entry retires
# a slice of the legacy flat-stub-page entries by providing real
# code in a real loaded DLL.
# ----------------------------------------------------------------------------
duetos_embed_blob(generated_customdll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-customdll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/customdll/customdll.c"
    COMMENT "Compiling + embedding customdll.dll (EAT parser fixture)")

duetos_embed_blob(generated_customdll2.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-customdll2.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/customdll2/customdll2.c"
    COMMENT "Compiling + embedding customdll2.dll (multi-DLL preload fixture)")

duetos_embed_blob(generated_kernel32_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-kernel32-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32.c"
    COMMENT "Compiling + embedding kernel32.dll (first stub retirement)")

duetos_embed_blob(generated_vcruntime140_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-vcruntime140-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/vcruntime140.c"
    COMMENT "Compiling + embedding vcruntime140.dll (memset/memcpy/memmove retirement)")

duetos_embed_blob(generated_msvcrt_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-msvcrt-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt/msvcrt.c"
    COMMENT "Compiling + embedding msvcrt.dll (string intrinsics retirement)")

duetos_embed_blob(generated_ntdll_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-ntdll-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll.c"
    COMMENT "Compiling + embedding ntdll.dll (Nt* / Zw* / Rtl* / Ldr* retirement)")

duetos_embed_blob(generated_dbghelp_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-dbghelp-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/dbghelp/dbghelp.c"
    COMMENT "Compiling + embedding dbghelp.dll (Sym* no-ops)")

duetos_embed_blob(generated_msvcp140_dll.h
    SCRIPT     "${CMAKE_SOURCE_DIR}/tools/build/build-msvcp140-dll.sh"
    SRC        "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.c"
    EXTRA_DEPS "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.def"
    COMMENT    "Compiling + embedding msvcp140.dll (C++ std throw + ostream helpers)")

duetos_embed_blob(generated_kernelbase_dll.h
    SCRIPT     "${CMAKE_SOURCE_DIR}/tools/build/build-kernelbase-dll.sh"
    SRC        "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.c"
    EXTRA_DEPS "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.def"
    COMMENT    "Compiling + embedding kernelbase.dll (forwarders -> kernel32)")

duetos_embed_blob(generated_advapi32_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-advapi32-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/advapi32/advapi32.c"
    COMMENT "Compiling + embedding advapi32.dll (Reg* / token / GetUserName / RtlGenRandom)")

duetos_embed_blob(generated_ucrtbase_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-ucrtbase-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/ucrtbase/ucrtbase.c"
    COMMENT "Compiling + embedding ucrtbase.dll (heap + exit + CRT startup retirement)")

# ----------------------------------------------------------------------------
# Generic stub DLLs — small, hand-written .c source + an export list
# passed on the build-script command line. tools/build/build-stub-dll.sh
# is the shared compiler invocation for all of these.
# ----------------------------------------------------------------------------
set(DUETOS_STUB_DLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build/build-stub-dll.sh")

macro(duetos_stub_dll name base_va exports)
    set(_src "${CMAKE_SOURCE_DIR}/userland/libs/${name}/${name}.c")
    set(_header "${CMAKE_CURRENT_BINARY_DIR}/generated_${name}_dll.h")
    add_custom_command(
        OUTPUT "${_header}"
        COMMAND "${DUETOS_STUB_DLL_SCRIPT}"
                "${CMAKE_SOURCE_DIR}" "${_header}" "${name}" "${base_va}" "${exports}"
        DEPENDS "${_src}" "${DUETOS_STUB_DLL_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Compiling + embedding ${name}.dll"
        VERBATIM
    )
    list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_header}")
endmacro()

duetos_stub_dll(shlwapi 0x100B0000 "PathAddBackslashW,PathAppendW,PathCombineW,PathFileExistsA,PathFileExistsW,PathFindExtensionA,PathFindExtensionW,PathFindFileNameA,PathFindFileNameW,PathIsDirectoryW,PathRemoveFileSpecW,PathStripPathW,StrCmpNW,StrCmpW,StrStrIW,StrStrW")
duetos_stub_dll(shell32 0x100C0000 "CommandLineToArgvW,ExtractIconW,ExtractIconExW,SHCreateDirectoryW,SHCreateDirectoryExW,SHFileOperationW,SHGetFolderPathA,SHGetFolderPathW,SHGetKnownFolderPath,SHGetPathFromIDListW,SHGetSpecialFolderPathW,ShellExecuteW,ShellExecuteExW")
duetos_stub_dll(ole32 0x100D0000 "CoInitialize,CoInitializeEx,CoUninitialize,OleInitialize,OleUninitialize,CoCreateInstance,CoCreateInstanceEx,CoGetClassObject,CLSIDFromString,CLSIDFromProgID,IIDFromString,StringFromCLSID,CoTaskMemAlloc,CoTaskMemFree,CoTaskMemRealloc")
duetos_stub_dll(oleaut32 0x100E0000 "VariantInit,VariantClear,SysAllocString,SysFreeString,SysStringLen")
duetos_stub_dll(winmm 0x100F0000 "timeGetTime,timeBeginPeriod,timeEndPeriod,timeGetDevCaps,timeSetEvent,timeKillEvent,PlaySoundW,mciSendStringW")
duetos_stub_dll(bcrypt 0x10100000 "BCryptOpenAlgorithmProvider,BCryptCloseAlgorithmProvider,BCryptCreateHash,BCryptHashData,BCryptFinishHash,BCryptDestroyHash,BCryptGetProperty,BCryptGenRandom")
duetos_stub_dll(psapi 0x10110000 "EnumProcesses,EnumProcessModules,GetMappedFileNameW,GetModuleBaseNameW,GetModuleFileNameExW,GetProcessMemoryInfo,QueryWorkingSet")

# DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs that produce working
# Clear-and-Present pipelines via SYS_GDI_BITBLT.
duetos_stub_dll(d3d9 0x10120000 "Direct3DCreate9,Direct3DCreate9Ex")
duetos_stub_dll(d3d11 0x10130000 "D3D11CreateDevice,D3D11CreateDeviceAndSwapChain")
duetos_stub_dll(d3d12 0x10140000 "D3D12CreateDevice,D3D12GetDebugInterface,D3D12SerializeRootSignature")
duetos_stub_dll(dxgi 0x10150000 "CreateDXGIFactory,CreateDXGIFactory1,CreateDXGIFactory2,DXGIGetDebugInterface,DXGIGetDebugInterface1,DXGIDeclareAdapterRemovalSupport")
duetos_stub_dll(user32 0x10160000 "BeginPaint,Beep,CallWindowProcA,CallWindowProcW,CharLowerW,CharUpperW,ClientToScreen,ClipCursor,CloseClipboard,CreateCaret,CreateWindowExA,CreateWindowExW,DefWindowProcA,DefWindowProcW,DestroyCaret,DestroyWindow,DispatchMessageA,DispatchMessageW,EmptyClipboard,EndPaint,EnumWindows,FindWindowA,FindWindowExA,FindWindowExW,FindWindowW,GetActiveWindow,GetAsyncKeyState,GetCapture,GetCaretBlinkTime,GetClientRect,GetClipboardData,GetCursorPos,GetDesktopWindow,GetFocus,GetForegroundWindow,GetKeyState,GetMessageA,GetMessageW,GetParent,GetProcessWindowStation,GetSysColor,GetSystemMetrics,GetWindow,GetWindowLongA,GetWindowLongPtrA,GetWindowLongPtrW,GetWindowLongW,GetWindowRect,GetWindowTextA,GetWindowTextW,HideCaret,InvalidateRect,IsWindow,KillTimer,LoadAcceleratorsA,LoadAcceleratorsW,LoadBitmapA,LoadBitmapW,LoadCursorA,LoadCursorW,LoadIconA,LoadIconW,LoadImageA,LoadImageW,LoadMenuA,LoadMenuW,LoadStringA,LoadStringW,MessageBeep,MessageBoxA,MessageBoxExA,MessageBoxExW,MessageBoxW,MoveWindow,OpenClipboard,PeekMessageA,PeekMessageW,PostMessageA,PostMessageW,PostQuitMessage,PostThreadMessageA,PostThreadMessageW,RegisterClassA,RegisterClassExA,RegisterClassExW,RegisterClassW,ReleaseCapture,ScreenToClient,SendMessageA,SendMessageW,SendNotifyMessageA,SendNotifyMessageW,SetActiveWindow,SetCapture,SetCaretBlinkTime,SetCaretPos,SetClipboardData,SetCursor,SetCursorPos,SetFocus,SetForegroundWindow,SetParent,SetTimer,SetWindowLongA,SetWindowLongPtrA,SetWindowLongPtrW,SetWindowLongW,SetWindowPos,SetWindowTextA,SetWindowTextW,ShowCaret,ShowCursor,ShowWindow,TranslateAcceleratorA,TranslateAcceleratorW,TranslateMessage,UnregisterClassA,UnregisterClassW,UpdateWindow,ValidateRect")
duetos_stub_dll(gdi32 0x10180000 "BitBlt,CreateBitmap,CreateBrushIndirect,CreateCompatibleBitmap,CreateCompatibleDC,CreateDIBSection,CreateDIBitmap,CreateFontA,CreateFontIndirectA,CreateFontIndirectW,CreateFontW,CreatePen,CreateSolidBrush,DeleteDC,DeleteObject,DrawTextA,DrawTextW,Ellipse,ExtTextOutA,ExtTextOutW,FillRect,FrameRect,GetDC,GetObjectA,GetObjectW,GetPixel,GetStockObject,GetWindowDC,LineTo,MoveToEx,Polygon,Polyline,Rectangle,ReleaseDC,RestoreDC,SaveDC,SelectObject,SetBkColor,SetBkMode,SetMapMode,SetPixel,SetPixelV,SetTextAlign,SetTextColor,StretchBlt,TextOutA,TextOutW")

# Stage-2 slice 31 — networking / crypto / common UI / version / setup.
duetos_stub_dll(ws2_32 0x10190000 "WSAStartup,WSACleanup,WSAGetLastError,WSASetLastError,socket,closesocket,bind,listen,connect,accept,send,recv,sendto,recvfrom,shutdown,setsockopt,getsockopt,select,htons,ntohs,htonl,ntohl,inet_addr,gethostbyname,gethostname,getaddrinfo,freeaddrinfo")
duetos_stub_dll(wininet 0x101A0000 "InternetOpenA,InternetOpenW,InternetConnectA,HttpOpenRequestA,HttpSendRequestA,InternetReadFile,InternetCloseHandle,InternetOpenUrlA")
duetos_stub_dll(winhttp 0x101B0000 "WinHttpOpen,WinHttpConnect,WinHttpOpenRequest,WinHttpSendRequest,WinHttpReceiveResponse,WinHttpReadData,WinHttpCloseHandle")
duetos_stub_dll(crypt32 0x101C0000 "CertOpenStore,CertCloseStore,CertFindCertificateInStore,CertFreeCertificateContext,CryptAcquireContextA,CryptReleaseContext,CryptGenRandom,CryptProtectData,CryptUnprotectData")
duetos_stub_dll(comctl32 0x101D0000 "InitCommonControls,InitCommonControlsEx,CreateStatusWindowA,CreateStatusWindowW,PropertySheetA,PropertySheetW,ImageList_Create,ImageList_Destroy")
duetos_stub_dll(comdlg32 0x101E0000 "GetOpenFileNameA,GetOpenFileNameW,GetSaveFileNameA,GetSaveFileNameW,ChooseColorA,ChooseColorW,ChooseFontA,ChooseFontW,PrintDlgA,PrintDlgW,CommDlgExtendedError")
duetos_stub_dll(version 0x101F0000 "GetFileVersionInfoSizeA,GetFileVersionInfoSizeW,GetFileVersionInfoA,GetFileVersionInfoW,VerQueryValueA,VerQueryValueW")
duetos_stub_dll(setupapi 0x10200000 "SetupDiGetClassDevsA,SetupDiGetClassDevsW,SetupDiDestroyDeviceInfoList,SetupDiEnumDeviceInfo,SetupOpenInfFileA,SetupOpenInfFileW,SetupCloseInfFile")

# Stage-2 slice 33 — six more support DLLs.
duetos_stub_dll(iphlpapi 0x10210000 "GetAdaptersInfo,GetAdaptersAddresses,GetIfTable,GetNumberOfInterfaces,IcmpSendEcho,IcmpCreateFile,IcmpCloseHandle")
duetos_stub_dll(userenv 0x10220000 "GetUserProfileDirectoryA,GetUserProfileDirectoryW,GetAllUsersProfileDirectoryW,CreateEnvironmentBlock,DestroyEnvironmentBlock,LoadUserProfileW,UnloadUserProfile")
duetos_stub_dll(wtsapi32 0x10230000 "WTSQuerySessionInformationA,WTSQuerySessionInformationW,WTSFreeMemory,WTSEnumerateSessionsW,WTSRegisterSessionNotification,WTSUnRegisterSessionNotification")
duetos_stub_dll(dwmapi 0x10240000 "DwmIsCompositionEnabled,DwmEnableComposition,DwmExtendFrameIntoClientArea,DwmGetWindowAttribute,DwmSetWindowAttribute,DwmFlush")
duetos_stub_dll(uxtheme 0x10250000 "OpenThemeData,CloseThemeData,IsThemeActive,IsAppThemed,SetWindowTheme,GetThemeSysFont,DrawThemeBackground,DrawThemeText")
duetos_stub_dll(secur32 0x10260000 "AcquireCredentialsHandleA,FreeCredentialsHandle,InitializeSecurityContextA,DeleteSecurityContext,GetUserNameExA,GetUserNameExW")


set(DUETOS_KERNEL_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/linker.ld")

# Shared link flags — applied identically to both stages so the symbol
# addresses extracted from stage 1 are valid for stage 2.
function(duetos_apply_kernel_link_flags target)
    target_link_options(${target} PRIVATE
        -T${DUETOS_KERNEL_LINKER_SCRIPT}
        -Wl,--gc-sections
        -Wl,--no-undefined
        -Wl,-n
    )
    set_target_properties(${target} PROPERTIES
        LINK_DEPENDS "${DUETOS_KERNEL_LINKER_SCRIPT}"
    )
endfunction()

# ----------------------------------------------------------------------------
# Stage 1: kernel with a stub symbol table. Throwaway — only exists so
# gen-symbols.sh has a linked ELF to read addresses out of.
#
# IMPORTANT: `symbols_stub.cpp` MUST be the last source in this list so
# the linker places its (near-empty) .rodata contribution at the very
# end of .rodata. The stage-2 kernel swaps in `symbols_generated.cpp`
# in the same trailing slot; rodata grows tail-ward and every other
# symbol's VA is preserved.
# ----------------------------------------------------------------------------
add_executable(duetos-kernel-stage1
    ${DUETOS_KERNEL_SHARED_SOURCES}
    util/symbols_stub.cpp
)
set_target_properties(duetos-kernel-stage1 PROPERTIES
    OUTPUT_NAME "duetos-kernel-stage1.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    # Stage 1 is internal plumbing — don't install or package it.
    EXCLUDE_FROM_ALL FALSE
)
target_include_directories(duetos-kernel-stage1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
duetos_apply_kernel_link_flags(duetos-kernel-stage1)

# ----------------------------------------------------------------------------
# Generate symbols_generated.cpp from the stage-1 ELF.
#
# gen-symbols.sh reads every higher-half function symbol, resolves
# addr -> (file, line) via addr2line, and emits a sorted-by-address
# `{addr, size, line, name, file}` table. The resulting TU is what the
# stage-2 kernel links against.
# ----------------------------------------------------------------------------
set(DUETOS_SYMBOLS_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/symbols_generated.cpp")

add_custom_command(
    OUTPUT "${DUETOS_SYMBOLS_GENERATED}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/build/gen-symbols.sh"
            "$<TARGET_FILE:duetos-kernel-stage1>"
            "${DUETOS_SYMBOLS_GENERATED}"
            "${CMAKE_SOURCE_DIR}"
    DEPENDS duetos-kernel-stage1 "${CMAKE_SOURCE_DIR}/tools/build/gen-symbols.sh"
    COMMENT "Extracting kernel symbol table from stage-1 ELF"
    VERBATIM
)

# ----------------------------------------------------------------------------
# Stage 2: final kernel. Same source set as stage 1, but the stub is
# replaced by the generated TU. The generated TU defines the same
# three extern "C" symbols the resolver looks up, now populated with
# real data.
# ----------------------------------------------------------------------------
add_executable(duetos-kernel
    ${DUETOS_KERNEL_SHARED_SOURCES}
    "${DUETOS_SYMBOLS_GENERATED}"
)

# Deliberate-panic build flag, consumed by kernel_main and triggered
# by tools/debug/test-panic.sh. OFF for normal builds — the demo panic
# halts the kernel on purpose and must not ship in a release preset.
option(DUETOS_PANIC_DEMO "Insert a deliberate Panic() at end of kernel_main (test-panic.sh)" OFF)
if(DUETOS_PANIC_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_PANIC_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_PANIC_DEMO=1)
endif()

# Deliberate stack-smash build flag. Enables a small in-kernel_main
# block that overruns a local array past its stack canary, forcing
# __stack_chk_fail to fire on return. Intended for verifying the
# canary infrastructure works end-to-end; OFF for normal builds.
option(DUETOS_CANARY_DEMO "Insert a deliberate stack smash at end of kernel_main (verifies stack-canary panic path)" OFF)
if(DUETOS_CANARY_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_CANARY_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_CANARY_DEMO=1)
endif()

# Red-team attack-simulation flag. Runs the AttackSim suite once
# at the end of kernel_main, exercising every runtime-checker
# detector by performing the attack a rootkit would and
# verifying the detector catches it. OFF for normal boot — the
# simulations escalate the security guard to Enforce mode and
# the block write-guard to Deny, which would poison every
# subsequent image load / sensitive-LBA write for the session.
option(DUETOS_ATTACK_SIM "Run the AttackSim red-team suite at end of kernel_main" OFF)
if(DUETOS_ATTACK_SIM)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_ATTACK_SIM=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_ATTACK_SIM=1)
endif()


# Deliberate-CPU-exception build flag, consumed by kernel_main and
# triggered by tools/debug/test-trap.sh. Executes `ud2` to take a #UD fault
# so the trap dispatcher's crash-dump path can be verified end-to-end
# (extractable BEGIN/END record, symbolized RIP, backtrace). OFF for
# normal builds.
option(DUETOS_TRAP_DEMO "Execute ud2 at end of kernel_main to take #UD (test-trap.sh)" OFF)
if(DUETOS_TRAP_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_TRAP_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_TRAP_DEMO=1)
endif()


# Initial boot mode: desktop (windowed shell) vs TTY (fullscreen
# framebuffer console). Runtime toggle with Ctrl+Alt+T works
# regardless of this flag; it only affects what the user sees
# when the kernel first hits kernel_main's compose phase. Useful
# for an install / rescue build that prefers text-first UX.
option(DUETOS_BOOT_TTY "Boot straight into TTY mode instead of the windowed desktop" OFF)
if(DUETOS_BOOT_TTY)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_BOOT_TTY=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_BOOT_TTY=1)
endif()

set_target_properties(duetos-kernel PROPERTIES
    OUTPUT_NAME "duetos-kernel.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(duetos-kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

duetos_apply_kernel_link_flags(duetos-kernel)

# ----------------------------------------------------------------------------
# Bootable ISO — uses GRUB as a third-party loader until our own UEFI boot
# loader exists. If grub-mkrescue / xorriso aren't installed, the kernel
# still builds; only the `duetos-iso` target is skipped, with a status
# message explaining what to install.
# ----------------------------------------------------------------------------

find_program(GRUB_MKRESCUE grub-mkrescue)
find_program(XORRISO       xorriso)

if(GRUB_MKRESCUE AND XORRISO)
    set(DUETOS_ISO_STAGE  "${CMAKE_CURRENT_BINARY_DIR}/iso-stage")
    set(DUETOS_ISO_OUTPUT "${CMAKE_BINARY_DIR}/duetos.iso")
    set(DUETOS_GRUB_CFG   "${CMAKE_SOURCE_DIR}/boot/grub/grub.cfg")

    add_custom_command(
        OUTPUT "${DUETOS_ISO_OUTPUT}"

        # Lay out the ISO root exactly the way grub.cfg expects.
        COMMAND ${CMAKE_COMMAND} -E rm -rf  "${DUETOS_ISO_STAGE}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DUETOS_ISO_STAGE}/boot/grub"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:duetos-kernel>"
                                         "${DUETOS_ISO_STAGE}/boot/duetos-kernel.elf"
        COMMAND ${CMAKE_COMMAND} -E copy "${DUETOS_GRUB_CFG}"
                                         "${DUETOS_ISO_STAGE}/boot/grub/grub.cfg"

        # Produce the ISO. grub-mkrescue embeds the i386-pc boot image so the
        # result is bootable on both legacy BIOS (via QEMU's default SeaBIOS)
        # and — when GRUB's EFI modules are present on the host — UEFI.
        COMMAND ${GRUB_MKRESCUE} --compress=xz -o "${DUETOS_ISO_OUTPUT}"
                                 "${DUETOS_ISO_STAGE}"

        DEPENDS duetos-kernel "${DUETOS_GRUB_CFG}"
        COMMENT "Building bootable duetos.iso"
        VERBATIM
    )

    add_custom_target(duetos-iso ALL
        DEPENDS "${DUETOS_ISO_OUTPUT}"
    )
else()
    message(STATUS "duetos-iso target disabled (grub-mkrescue or xorriso not found).")
    message(STATUS "  Install with: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools")
endif()
