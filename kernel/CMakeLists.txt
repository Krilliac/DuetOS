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

# /bin/usershell.elf — real userland shell binary built from
# userland/shell/shell.c against userland/libc/. Replaces the
# previous hand-coded 181-byte ELF stub. The build script
# compiles crt0.S + syscall.c + shell.c, links static via lld,
# and embeds the resulting bytes for ramfs.
duetos_embed_blob(generated_usershell_elf.h
    SCRIPT      "${CMAKE_SOURCE_DIR}/tools/build/build-usershell-elf.sh"
    SRC         "${CMAKE_SOURCE_DIR}/userland/shell/shell.c"
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/userland/libc/src/crt0.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/syscall.c"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/duet/syscall.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/string.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/unistd.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/usershell.lds"
    COMMENT     "Compiling + embedding /bin/usershell.elf (real userland shell)")

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

# /bin/synxtest.elf — freestanding Linux-ABI exerciser. No libc, no
# crt — synxtest.c defines _start and inline syscall asm. The kernel
# spawns it via SpawnSynxTestElf to print pass/fail tags per Linux
# syscall, surfacing live coverage of the ABI on every boot.
duetos_embed_blob(generated_synxtest_elf.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-synxtest.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/synxtest/synxtest.c"
    COMMENT "Compiling + embedding /bin/synxtest.elf (Linux-ABI exerciser)")

# /bin/synfs.elf — sister of synxtest. Targets FS-mutation
# syscalls (mkdir/rmdir/rename/chmod/truncate/unlink/copy_file_range/...)
# and runs with kCapFsRead + kCapFsWrite so each call actually
# reaches the filesystem instead of bouncing off the cap gate.
duetos_embed_blob(generated_synfs_elf.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-synfs.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/synfs/synfs.c"
    COMMENT "Compiling + embedding /bin/synfs.elf (Linux-ABI FS-mut exerciser)")

# /bin/synet.elf — sister of synfs. Targets socket-family syscalls
# (socket/bind/listen/accept/connect/sendto/recvfrom/setsockopt/
# getsockopt/...) and runs with kCapNet so each call actually
# reaches the kernel handler.
duetos_embed_blob(generated_synet_elf.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-synet.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/synet/synet.c"
    COMMENT "Compiling + embedding /bin/synet.elf (Linux-ABI socket exerciser)")

# /bin/synfull.elf — exhaustive Linux-ABI exerciser. Issues every
# spec syscall (0..462) with zero-args, prints rc per call. Spawned
# with all caps so cap-gated calls reach their real handler.
duetos_embed_blob(generated_synfull_elf.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-synfull.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/synfull/synfull.c"
    COMMENT "Compiling + embedding /bin/synfull.elf (Linux-ABI exhaustive exerciser)")

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

# mini_browser.exe — minimal WinSock 2 PE that does an HTTP/1.0 GET to
# www.google.com. Source is userland/apps/mini_browser/browser.c; the
# prebuilt PE checked into the tree is what gets embedded so the
# kernel build doesn't depend on mingw-w64 being installed. Rebuild
# via userland/apps/mini_browser/build.sh when the source changes.
set(DUETOS_MINIBROWSER_SRC    "${CMAKE_SOURCE_DIR}/userland/apps/mini_browser/browser.exe")
set(DUETOS_MINIBROWSER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_minibrowser_pe.h")
add_custom_command(
    OUTPUT "${DUETOS_MINIBROWSER_HEADER}"
    COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_MINIBROWSER_SRC}" "${DUETOS_MINIBROWSER_HEADER}"
            kBinMiniBrowserBytes --namespace "duetos::fs::generated"
    DEPENDS "${DUETOS_MINIBROWSER_SRC}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding mini_browser PE /bin/mini_browser.exe"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_MINIBROWSER_HEADER}")

# Surface-coverage PE smoke apps. Each one is a self-contained
# console PE (~10 KB) targeting a single Win32 API surface.
# Source lives in userland/apps/<name>/<name>.c; rebuild with
# userland/apps/build-smokes.sh when sources change.
function(duetos_embed_smoke_pe app_name symbol)
    set(_src "${CMAKE_SOURCE_DIR}/userland/apps/${app_name}/${app_name}.exe")
    set(_hdr "${CMAKE_CURRENT_BINARY_DIR}/generated_${app_name}_pe.h")
    add_custom_command(
        OUTPUT "${_hdr}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${_src}" "${_hdr}"
                "${symbol}" --namespace "duetos::fs::generated"
        DEPENDS "${_src}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding ${app_name} PE"
        VERBATIM)
    set(DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_KERNEL_SHARED_SOURCES}" "${_hdr}" PARENT_SCOPE)
endfunction()

duetos_embed_smoke_pe(crypto_smoke   kBinCryptoSmokeBytes)
duetos_embed_smoke_pe(paths_smoke    kBinPathsSmokeBytes)
duetos_embed_smoke_pe(time_smoke     kBinTimeSmokeBytes)
duetos_embed_smoke_pe(wininet_smoke  kBinWininetSmokeBytes)
duetos_embed_smoke_pe(iphlpapi_smoke kBinIphlpapiSmokeBytes)
duetos_embed_smoke_pe(string_smoke   kBinStringSmokeBytes)
duetos_embed_smoke_pe(mem_smoke      kBinMemSmokeBytes)
duetos_embed_smoke_pe(fs_smoke       kBinFsSmokeBytes)
duetos_embed_smoke_pe(registry_smoke kBinRegistrySmokeBytes)
duetos_embed_smoke_pe(handle_smoke   kBinHandleSmokeBytes)
duetos_embed_smoke_pe(process_smoke  kBinProcessSmokeBytes)
duetos_embed_smoke_pe(module_smoke   kBinModuleSmokeBytes)
duetos_embed_smoke_pe(env_smoke      kBinEnvSmokeBytes)
duetos_embed_smoke_pe(debug_smoke    kBinDebugSmokeBytes)
duetos_embed_smoke_pe(codepage_smoke kBinCodepageSmokeBytes)
duetos_embed_smoke_pe(rng_smoke      kBinRngSmokeBytes)
duetos_embed_smoke_pe(version_smoke  kBinVersionSmokeBytes)
duetos_embed_smoke_pe(psapi_smoke    kBinPsapiSmokeBytes)
duetos_embed_smoke_pe(com_smoke      kBinComSmokeBytes)
duetos_embed_smoke_pe(dbghelp_smoke  kBinDbghelpSmokeBytes)
duetos_embed_smoke_pe(winhttp_smoke  kBinWinhttpSmokeBytes)
duetos_embed_smoke_pe(crt_smoke      kBinCrtSmokeBytes)
duetos_embed_smoke_pe(critsec_smoke  kBinCritsecSmokeBytes)
duetos_embed_smoke_pe(tls_smoke      kBinTlsSmokeBytes)
duetos_embed_smoke_pe(atom_smoke     kBinAtomSmokeBytes)
duetos_embed_smoke_pe(console_smoke  kBinConsoleSmokeBytes)
duetos_embed_smoke_pe(datetime_smoke kBinDatetimeSmokeBytes)
duetos_embed_smoke_pe(locale_smoke   kBinLocaleSmokeBytes)
duetos_embed_smoke_pe(gdi_smoke      kBinGdiSmokeBytes)
duetos_embed_smoke_pe(msg_smoke      kBinMsgSmokeBytes)
duetos_embed_smoke_pe(pipe_smoke     kBinPipeSmokeBytes)
duetos_embed_smoke_pe(resource_smoke kBinResourceSmokeBytes)
duetos_embed_smoke_pe(ntdll_smoke    kBinNtdllSmokeBytes)
duetos_embed_smoke_pe(shell_smoke    kBinShellSmokeBytes)
duetos_embed_smoke_pe(userenv_smoke  kBinUserenvSmokeBytes)
duetos_embed_smoke_pe(interlock_smoke kBinInterlockSmokeBytes)
duetos_embed_smoke_pe(fiber_smoke    kBinFiberSmokeBytes)
duetos_embed_smoke_pe(profile_smoke  kBinProfileSmokeBytes)
duetos_embed_smoke_pe(clipboard_smoke kBinClipboardSmokeBytes)
duetos_embed_smoke_pe(windowclass_smoke kBinWindowclassSmokeBytes)
duetos_embed_smoke_pe(wow64_smoke    kBinWow64SmokeBytes)
duetos_embed_smoke_pe(mathlib_smoke  kBinMathlibSmokeBytes)
duetos_embed_smoke_pe(stdio_smoke    kBinStdioSmokeBytes)
duetos_embed_smoke_pe(nls_smoke      kBinNlsSmokeBytes)
duetos_embed_smoke_pe(services_smoke kBinServicesSmokeBytes)
duetos_embed_smoke_pe(eventlog_smoke kBinEventlogSmokeBytes)
duetos_embed_smoke_pe(sound_smoke    kBinSoundSmokeBytes)
duetos_embed_smoke_pe(multimon_smoke kBinMultimonSmokeBytes)
duetos_embed_smoke_pe(power_smoke    kBinPowerSmokeBytes)
duetos_embed_smoke_pe(heap_smoke     kBinHeapSmokeBytes)
duetos_embed_smoke_pe(thread2_smoke  kBinThread2SmokeBytes)
duetos_embed_smoke_pe(ipc_smoke      kBinIpcSmokeBytes)
duetos_embed_smoke_pe(jobobj_smoke   kBinJobobjSmokeBytes)
duetos_embed_smoke_pe(console2_smoke kBinConsole2SmokeBytes)
duetos_embed_smoke_pe(dns_smoke      kBinDnsSmokeBytes)
duetos_embed_smoke_pe(network2_smoke kBinNetwork2SmokeBytes)
duetos_embed_smoke_pe(dxgi_smoke     kBinDxgiSmokeBytes)
duetos_embed_smoke_pe(dwm_smoke      kBinDwmSmokeBytes)
duetos_embed_smoke_pe(uxtheme_smoke  kBinUxthemeSmokeBytes)
duetos_embed_smoke_pe(token_smoke    kBinTokenSmokeBytes)
duetos_embed_smoke_pe(security_smoke kBinSecuritySmokeBytes)
duetos_embed_smoke_pe(perf_smoke     kBinPerfSmokeBytes)
duetos_embed_smoke_pe(accel_smoke    kBinAccelSmokeBytes)
duetos_embed_smoke_pe(wts_smoke      kBinWtsSmokeBytes)
duetos_embed_smoke_pe(winerr_smoke   kBinWinerrSmokeBytes)
duetos_embed_smoke_pe(sleep_smoke    kBinSleepSmokeBytes)
duetos_embed_smoke_pe(nt_smoke       kBinNtSmokeBytes)
duetos_embed_smoke_pe(vol_smoke      kBinVolSmokeBytes)
duetos_embed_smoke_pe(drive_smoke    kBinDriveSmokeBytes)
duetos_embed_smoke_pe(conio_smoke    kBinConioSmokeBytes)
duetos_embed_smoke_pe(mbcs_smoke     kBinMbcsSmokeBytes)
duetos_embed_smoke_pe(fpcontrol_smoke kBinFpcontrolSmokeBytes)
duetos_embed_smoke_pe(locale2_smoke  kBinLocale2SmokeBytes)
duetos_embed_smoke_pe(gdiplus_smoke  kBinGdiplusSmokeBytes)
duetos_embed_smoke_pe(dde_smoke      kBinDdeSmokeBytes)
duetos_embed_smoke_pe(stream_smoke   kBinStreamSmokeBytes)
duetos_embed_smoke_pe(setupapi_smoke kBinSetupapiSmokeBytes)
duetos_embed_smoke_pe(asyn_smoke     kBinAsynSmokeBytes)
duetos_embed_smoke_pe(wndmsg_smoke   kBinWndmsgSmokeBytes)
duetos_embed_smoke_pe(scrap_smoke    kBinScrapSmokeBytes)
duetos_embed_smoke_pe(trace_smoke    kBinTraceSmokeBytes)
duetos_embed_smoke_pe(wmi_smoke      kBinWmiSmokeBytes)
duetos_embed_smoke_pe(enviro_smoke   kBinEnviroSmokeBytes)
duetos_embed_smoke_pe(select_smoke   kBinSelectSmokeBytes)
duetos_embed_smoke_pe(proc2_smoke    kBinProc2SmokeBytes)
duetos_embed_smoke_pe(find_smoke     kBinFindSmokeBytes)
duetos_embed_smoke_pe(iocp2_smoke    kBinIocp2SmokeBytes)
duetos_embed_smoke_pe(signal_smoke   kBinSignalSmokeBytes)
duetos_embed_smoke_pe(timer_smoke    kBinTimerSmokeBytes)
duetos_embed_smoke_pe(winsock_ext_smoke kBinWinsockExtSmokeBytes)
duetos_embed_smoke_pe(key_smoke      kBinKeySmokeBytes)
duetos_embed_smoke_pe(reg2_smoke     kBinReg2SmokeBytes)
duetos_embed_smoke_pe(paths2_smoke   kBinPaths2SmokeBytes)
duetos_embed_smoke_pe(advapi_smoke   kBinAdvapiSmokeBytes)
duetos_embed_smoke_pe(heap3_smoke    kBinHeap3SmokeBytes)
duetos_embed_smoke_pe(thread3_smoke  kBinThread3SmokeBytes)
duetos_embed_smoke_pe(wstr_smoke     kBinWstrSmokeBytes)
duetos_embed_smoke_pe(intl_smoke     kBinIntlSmokeBytes)
duetos_embed_smoke_pe(disp_smoke     kBinDispSmokeBytes)
duetos_embed_smoke_pe(svc_ctrl_smoke kBinSvcCtrlSmokeBytes)
duetos_embed_smoke_pe(sysinfo_smoke  kBinSysinfoSmokeBytes)
duetos_embed_smoke_pe(mem2_smoke     kBinMem2SmokeBytes)
duetos_embed_smoke_pe(fs2_smoke      kBinFs2SmokeBytes)
duetos_embed_smoke_pe(console3_smoke kBinConsole3SmokeBytes)
duetos_embed_smoke_pe(xml_smoke      kBinXmlSmokeBytes)
duetos_embed_smoke_pe(reg3_smoke     kBinReg3SmokeBytes)
duetos_embed_smoke_pe(proc3_smoke    kBinProc3SmokeBytes)
duetos_embed_smoke_pe(com2_smoke     kBinCom2SmokeBytes)
duetos_embed_smoke_pe(advmem_smoke   kBinAdvmemSmokeBytes)
duetos_embed_smoke_pe(wstr2_smoke    kBinWstr2SmokeBytes)
duetos_embed_smoke_pe(fs3_smoke      kBinFs3SmokeBytes)
duetos_embed_smoke_pe(cap_smoke      kBinCapSmokeBytes)
duetos_embed_smoke_pe(utf16_smoke    kBinUtf16SmokeBytes)
duetos_embed_smoke_pe(handle2_smoke  kBinHandle2SmokeBytes)
duetos_embed_smoke_pe(sock_opt_smoke kBinSockOptSmokeBytes)
duetos_embed_smoke_pe(prio_smoke     kBinPrioSmokeBytes)
duetos_embed_smoke_pe(debug2_smoke   kBinDebug2SmokeBytes)
# DirectX v0 smoke suite — covers d3d{9,11,12} Clear+Present pipelines
# plus the new dinput8/xinput/xaudio2/dsound/ddraw/d2d1/dwrite peripheral
# DLLs through real COM vtable calls.
duetos_embed_smoke_pe(d3d11_smoke    kBinD3d11SmokeBytes)
duetos_embed_smoke_pe(d3d12_smoke    kBinD3d12SmokeBytes)
duetos_embed_smoke_pe(d3d9_smoke     kBinD3d9SmokeBytes)
duetos_embed_smoke_pe(dinput8_smoke  kBinDinput8SmokeBytes)
duetos_embed_smoke_pe(xinput_smoke   kBinXinputSmokeBytes)
duetos_embed_smoke_pe(xaudio2_smoke  kBinXaudio2SmokeBytes)
duetos_embed_smoke_pe(dsound_smoke   kBinDsoundSmokeBytes)
duetos_embed_smoke_pe(ddraw_smoke    kBinDdrawSmokeBytes)
duetos_embed_smoke_pe(d2d1_smoke     kBinD2d1SmokeBytes)
duetos_embed_smoke_pe(dwrite_smoke   kBinDwriteSmokeBytes)
# dx_demo: comprehensive DX exercise that pre-transforms a 24-vertex
# unit cube and rasterizes it through D3D9 (FF transforms), D3D11 and
# D3D12 (CPU-pretransformed verts), then reads back the back-buffer
# pixels and asserts at least one cube face is visible per backend.
duetos_embed_smoke_pe(dx_demo        kBinDxDemoBytes)
# dx_demo_window: visible 3D cube — renders the same cube as dx_demo
# into a real CreateWindowExA-spawned compositor window via a
# D3D11 swap chain bound to that HWND. Sleep(17s) keeps it on screen
# for the screenshot harness. Skipped under -enable-kvm (boot smoke).
duetos_embed_smoke_pe(dx_demo_window kBinDxDemoWindowBytes)

# Chrome font — Liberation Sans Regular (SIL OFL 1.1). Embedded as
# bytes for the TTF rasterizer; the boot path hands these to
# TtfLoad + TtfChromeFontSet so the 5 Duet-family themes start
# rendering window titles via the slice-4 rasterizer instead of
# the fallback 8x8 bitmap font.
set(DUETOS_CHROME_FONT_SRC    "${CMAKE_SOURCE_DIR}/userland/assets/fonts/duet-chrome.ttf")
set(DUETOS_CHROME_FONT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font.h")
add_custom_command(
    OUTPUT "${DUETOS_CHROME_FONT_HEADER}"
    COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_CHROME_FONT_SRC}" "${DUETOS_CHROME_FONT_HEADER}"
            kBinChromeFontBytes --namespace "duetos::drivers::video::generated"
    DEPENDS "${DUETOS_CHROME_FONT_SRC}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding chrome font Liberation Sans Regular (SIL OFL 1.1)"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_CHROME_FONT_HEADER}")

# Wallpaper SVG assets — DuetMark, topo backdrop, syscalls grid.
# Hand-authored under userland/assets/wallpapers/. Each gets its
# own embed entry so the wallpaper paint dispatch can walk them
# independently per theme.
foreach(_svg_name duet-mark topo syscalls-grid)
    set(_svg_src    "${CMAKE_SOURCE_DIR}/userland/assets/wallpapers/${_svg_name}.svg")
    set(_svg_header "${CMAKE_CURRENT_BINARY_DIR}/generated_svg_${_svg_name}.h")
    string(REPLACE "-" "_" _svg_underscore "${_svg_name}")
    add_custom_command(
        OUTPUT "${_svg_header}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${_svg_src}" "${_svg_header}"
                kBinSvg_${_svg_underscore}_Bytes
                --namespace "duetos::drivers::video::generated"
        DEPENDS "${_svg_src}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding wallpaper SVG ${_svg_name}.svg"
        VERBATIM)
    list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_svg_header}")
endforeach()

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

duetos_stub_dll(shlwapi 0x100B0000 "PathAddBackslashA,PathAddBackslashW,PathAppendW,PathCombineW,PathFileExistsA,PathFileExistsW,PathFindExtensionA,PathFindExtensionW,PathFindFileNameA,PathFindFileNameW,PathIsDirectoryW,PathRemoveFileSpecW,PathStripPathW,PathRemoveBackslashA,PathRemoveBackslashW,PathRemoveExtensionA,PathRemoveExtensionW,StrCmpA,StrCmpNA,StrCmpW,StrCmpNW,StrCmpIA,StrCmpIW,StrCmpNIA,StrCmpNIW,StrChrA,StrChrW,StrRChrA,StrRChrW,StrStrA,StrStrW,StrStrIA,StrStrIW,PathCanonicalizeW,PathRenameExtensionW,PathIsRelativeA,PathIsRelativeW,PathQuoteSpacesW,PathUnquoteSpacesW,PathMatchSpecW")
duetos_stub_dll(shell32 0x100C0000 "CommandLineToArgvW,ExtractIconW,ExtractIconExW,SHCreateDirectoryW,SHCreateDirectoryExW,SHFileOperationW,SHGetFolderPathA,SHGetFolderPathW,SHGetKnownFolderPath,SHGetPathFromIDListW,SHGetSpecialFolderPathW,ShellExecuteW,ShellExecuteExW")
duetos_stub_dll(ole32 0x100D0000 "CoInitialize,CoInitializeEx,CoUninitialize,CoInitializeSecurity,CoSetProxyBlanket,OleInitialize,OleUninitialize,CoCreateInstance,CoCreateInstanceEx,CoGetClassObject,CoGetMalloc,CLSIDFromString,CLSIDFromProgID,IIDFromString,StringFromCLSID,StringFromGUID2,CoTaskMemAlloc,CoTaskMemFree,CoTaskMemRealloc,CoRegisterClassObject,CoRevokeClassObject,CoResumeClassObjects,CoSuspendClassObjects,CoAddRefServerProcess,CoReleaseServerProcess,CreateStreamOnHGlobal,GetHGlobalFromStream,GetRunningObjectTable,RegisterDragDrop,RevokeDragDrop")
duetos_stub_dll(oleaut32 0x100E0000 "VariantInit,VariantClear,VariantCopy,SysAllocString,SysAllocStringLen,SysAllocStringByteLen,SysReAllocString,SysFreeString,SysStringLen,SysStringByteLen")
duetos_stub_dll(winmm 0x100F0000 "timeGetTime,timeBeginPeriod,timeEndPeriod,timeGetDevCaps,timeSetEvent,timeKillEvent,PlaySoundW,mciSendStringW")
duetos_stub_dll(bcrypt 0x10100000 "BCryptOpenAlgorithmProvider,BCryptCloseAlgorithmProvider,BCryptCreateHash,BCryptHashData,BCryptFinishHash,BCryptDestroyHash,BCryptGetProperty,BCryptGenRandom")
duetos_stub_dll(psapi 0x10110000 "EnumProcesses,EnumProcessModules,GetMappedFileNameW,GetModuleBaseNameW,GetModuleFileNameExW,GetProcessImageFileNameW,GetProcessImageFileNameA,GetProcessMemoryInfo,QueryWorkingSet,K32EnumProcesses,K32EnumProcessModules,K32EnumProcessModulesEx,K32GetMappedFileNameW,K32GetModuleBaseNameW,K32GetModuleFileNameExW,K32GetProcessImageFileNameW,K32GetProcessImageFileNameA,K32GetProcessMemoryInfo,K32QueryWorkingSet,GetPerformanceInfo,K32GetPerformanceInfo,EmptyWorkingSet,K32EmptyWorkingSet,GetWsChanges,K32GetWsChanges,InitializeProcessForWsWatch,K32InitializeProcessForWsWatch,GetModuleInformation,K32GetModuleInformation,EnumDeviceDrivers,K32EnumDeviceDrivers,GetDeviceDriverBaseNameA,GetDeviceDriverBaseNameW,K32GetDeviceDriverBaseNameA,K32GetDeviceDriverBaseNameW,GetDeviceDriverFileNameA,GetDeviceDriverFileNameW,QueryFullProcessImageNameA,QueryFullProcessImageNameW,GetMappedFileNameA,K32GetMappedFileNameA,GetModuleBaseNameA,K32GetModuleBaseNameA,GetModuleFileNameExA,K32GetModuleFileNameExA")

# DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs that produce working
# Clear-and-Present pipelines via SYS_GDI_BITBLT.
duetos_stub_dll(d3d9 0x10120000 "Direct3DCreate9,Direct3DCreate9Ex,DuetOS_D3D9_PeekBackBuffer")
duetos_stub_dll(d3d11 0x10130000 "D3D11CreateDevice,D3D11CreateDeviceAndSwapChain")
duetos_stub_dll(d3d12 0x10140000 "D3D12CreateDevice,D3D12GetDebugInterface,D3D12SerializeRootSignature,DuetOS_D3D12_PeekResourceState")
duetos_stub_dll(dxgi 0x10150000 "CreateDXGIFactory,CreateDXGIFactory1,CreateDXGIFactory2,DXGIGetDebugInterface,DXGIGetDebugInterface1,DXGIDeclareAdapterRemovalSupport")
duetos_stub_dll(user32 0x10160000 "BeginPaint,Beep,CallWindowProcA,CallWindowProcW,CharLowerA,CharLowerW,CharUpperA,CharUpperW,IsCharAlphaA,IsCharAlphaNumericA,IsCharAlphaW,IsCharAlphaNumericW,ClientToScreen,ClipCursor,CloseClipboard,CreateCaret,CreateWindowExA,CreateWindowExW,DefWindowProcA,DefWindowProcW,DestroyCaret,DestroyWindow,DispatchMessageA,DispatchMessageW,EmptyClipboard,EndPaint,EnumWindows,FindWindowA,FindWindowExA,FindWindowExW,FindWindowW,GetActiveWindow,GetAsyncKeyState,GetCapture,GetCaretBlinkTime,GetClientRect,GetClipboardData,GetCursorPos,GetDesktopWindow,GetFocus,GetForegroundWindow,GetKeyState,GetMessageA,GetMessageW,GetParent,GetProcessWindowStation,GetSysColor,GetSystemMetrics,GetWindow,GetWindowLongA,GetWindowLongPtrA,GetWindowLongPtrW,GetWindowLongW,GetWindowRect,GetWindowTextA,GetWindowTextW,HideCaret,InvalidateRect,IsWindow,KillTimer,LoadAcceleratorsA,LoadAcceleratorsW,LoadBitmapA,LoadBitmapW,LoadCursorA,LoadCursorW,LoadIconA,LoadIconW,LoadImageA,LoadImageW,LoadMenuA,LoadMenuW,LoadStringA,LoadStringW,MessageBeep,MessageBoxA,MessageBoxExA,MessageBoxExW,MessageBoxW,MoveWindow,OpenClipboard,PeekMessageA,PeekMessageW,PostMessageA,PostMessageW,PostQuitMessage,PostThreadMessageA,PostThreadMessageW,RegisterClassA,RegisterClassExA,RegisterClassExW,RegisterClassW,ReleaseCapture,ScreenToClient,SendMessageA,SendMessageW,SendNotifyMessageA,SendNotifyMessageW,SetActiveWindow,SetCapture,SetCaretBlinkTime,SetCaretPos,SetClipboardData,SetCursor,SetCursorPos,SetFocus,SetForegroundWindow,SetParent,SetTimer,SetWindowLongA,SetWindowLongPtrA,SetWindowLongPtrW,SetWindowLongW,SetWindowPos,SetWindowTextA,SetWindowTextW,ShowCaret,ShowCursor,ShowWindow,TranslateAcceleratorA,TranslateAcceleratorW,TranslateMessage,UnregisterClassA,UnregisterClassW,UpdateWindow,ValidateRect,EnumDisplayMonitors,MonitorFromPoint,MonitorFromWindow,GetMonitorInfoW,EnumDisplayDevicesW,EnumDisplaySettingsW,DdeInitializeA,DdeInitializeW,DdeUninitialize,DdeCreateStringHandleA,DdeCreateStringHandleW,DdeFreeStringHandle,GetClassInfoW,GetClassInfoExW,CreateAcceleratorTableW,CopyAcceleratorTableW,DestroyAcceleratorTable,GetDpiForSystem,GetDpiForWindow")
duetos_stub_dll(gdi32 0x10180000 "BitBlt,CreateBitmap,CreateBrushIndirect,CreateCompatibleBitmap,CreateCompatibleDC,CreateDIBSection,CreateDIBitmap,CreateFontA,CreateFontIndirectA,CreateFontIndirectW,CreateFontW,CreatePen,CreateSolidBrush,DeleteDC,DeleteObject,DrawTextA,DrawTextW,Ellipse,ExtTextOutA,ExtTextOutW,FillRect,FrameRect,GetDC,GetObjectA,GetObjectW,GetPixel,GetStockObject,GetWindowDC,LineTo,MoveToEx,Polygon,Polyline,Rectangle,ReleaseDC,RestoreDC,SaveDC,SelectObject,SetBkColor,SetBkMode,SetMapMode,SetPixel,SetPixelV,SetTextAlign,SetTextColor,StretchBlt,TextOutA,TextOutW")

# Stage-2 slice 31 — networking / crypto / common UI / version / setup.
duetos_stub_dll(ws2_32 0x10190000 "WSAStartup,WSACleanup,WSAGetLastError,WSASetLastError,socket,closesocket,bind,listen,connect,accept,send,recv,sendto,recvfrom,shutdown,setsockopt,getsockopt,select,__WSAFDIsSet,htons,ntohs,htonl,ntohl,inet_addr,inet_ntoa,inet_pton,inet_ntop,gethostbyname,gethostname,getaddrinfo,freeaddrinfo,htonll,ntohll,WSAEnumProtocolsA,WSAEnumProtocolsW,getnameinfo,WSAIoctl,ioctlsocket,getsockname,getpeername,WSACreateEvent,WSACloseEvent,WSASetEvent,WSAResetEvent")
duetos_stub_dll(wininet 0x101A0000 "InternetOpenA,InternetOpenW,InternetConnectA,InternetConnectW,HttpOpenRequestA,HttpOpenRequestW,HttpSendRequestA,HttpSendRequestW,InternetReadFile,InternetCloseHandle,InternetOpenUrlA,InternetOpenUrlW,InternetWriteFile,InternetQueryDataAvailable,InternetSetOptionA,InternetSetOptionW,InternetQueryOptionA,InternetQueryOptionW,HttpQueryInfoA,HttpQueryInfoW,InternetGetConnectedState,InternetCheckConnectionA,InternetCheckConnectionW,HttpAddRequestHeadersA,HttpAddRequestHeadersW,HttpEndRequestA,HttpEndRequestW,HttpSendRequestExA,HttpSendRequestExW,InternetReadFileExA,InternetReadFileExW,InternetGetCookieA,InternetGetCookieW,InternetSetCookieA,InternetSetCookieW,InternetGetCookieExA,InternetGetCookieExW,InternetCrackUrlA,InternetCrackUrlW,InternetCanonicalizeUrlA,InternetCanonicalizeUrlW,FtpFindFirstFileA,FtpFindFirstFileW,FtpGetFileA,FtpGetFileW,FtpPutFileA,FtpPutFileW,DeleteUrlCacheEntryA,DeleteUrlCacheEntryW,InternetTimeFromSystemTimeA,InternetTimeFromSystemTimeW,InternetTimeToSystemTimeA,InternetTimeToSystemTimeW,InternetGetLastResponseInfoA,InternetGetLastResponseInfoW")
duetos_stub_dll(winhttp 0x101B0000 "WinHttpOpen,WinHttpConnect,WinHttpOpenRequest,WinHttpSendRequest,WinHttpReceiveResponse,WinHttpReadData,WinHttpCloseHandle,WinHttpQueryDataAvailable,WinHttpQueryHeaders,WinHttpAddRequestHeaders,WinHttpSetOption,WinHttpQueryOption,WinHttpSetTimeouts,WinHttpSetStatusCallback,WinHttpCheckPlatform,WinHttpCrackUrl,WinHttpQueryAuthSchemes,WinHttpSetCredentials,WinHttpDetectAutoProxyConfigUrl,WinHttpGetIEProxyConfigForCurrentUser,WinHttpGetProxyForUrl,WinHttpGetDefaultProxyConfiguration,WinHttpSetDefaultProxyConfiguration,WinHttpResetAutoProxy,WinHttpCreateUrl,WinHttpTimeFromSystemTime,WinHttpTimeToSystemTime,WinHttpReadDataEx,WinHttpWriteData,WinHttpQueryDataAvailable2,WinHttpWebSocketCompleteUpgrade,WinHttpWebSocketSend,WinHttpWebSocketReceive,WinHttpWebSocketClose,WinHttpWebSocketShutdown")
duetos_stub_dll(crypt32 0x101C0000 "CertOpenStore,CertCloseStore,CertFindCertificateInStore,CertFreeCertificateContext,CryptAcquireContextA,CryptAcquireContextW,CryptReleaseContext,CryptGenRandom,CryptProtectData,CryptUnprotectData,CryptStringToBinaryA,CryptBinaryToStringA,CryptCreateHash,CryptHashData,CryptDestroyHash,CryptGetHashParam,CertEnumCertificatesInStore,CertGetNameStringW,CertGetNameStringA,CertVerifyCertificateChainPolicy,CertGetCertificateContextProperty,CertSetCertificateContextProperty,CertControlStore,CertNameToStrA,CertNameToStrW,PFXImportCertStore,PFXExportCertStore,PFXIsPFXBlob,CryptStringToBinaryW,CryptBinaryToStringW,CryptDecodeObject,CryptDecodeObjectEx,CryptEncodeObject,CryptEncodeObjectEx,CertAddCertificateContextToStore,CertDeleteCertificateFromStore,CertCreateCertificateContext,CertDuplicateCertificateContext,CryptVerifyCertificateSignature,CryptVerifyCertificateSignatureEx,CertGetIssuerCertificateFromStore,CertGetCertificateChain,CertFreeCertificateChain,CryptMsgOpenToDecode,CryptMsgUpdate,CryptMsgGetParam,CryptMsgClose,CryptSignAndEncryptMessage")
duetos_stub_dll(comctl32 0x101D0000 "InitCommonControls,InitCommonControlsEx,CreateStatusWindowA,CreateStatusWindowW,PropertySheetA,PropertySheetW,ImageList_Create,ImageList_Destroy,ImageList_AddIcon,ImageList_ReplaceIcon,ImageList_Draw,ImageList_GetImageCount,ImageList_GetIconSize,ImageList_SetImageCount,ImageList_LoadImageA,ImageList_LoadImageW,ImageList_BeginDrag,ImageList_EndDrag,ImageList_DragEnter,ImageList_DragLeave,ImageList_DragMove,DefSubclassProc,SetWindowSubclass,RemoveWindowSubclass,GetWindowSubclass,TaskDialog,TaskDialogIndirect,_TrackMouseEvent,DrawStatusTextA,DrawStatusTextW,CreateToolbarEx,CreateUpDownControl,CreateMappedBitmap,DPA_Create,DPA_Destroy,DPA_GetPtrCount,DPA_GetPtr,DSA_Create,DSA_Destroy,DSA_GetItemCount,GetMUILanguage,SetMUILanguage,InitMUILanguage,FlatSB_GetScrollInfo,FlatSB_SetScrollInfo,InitializeFlatSB,UninitializeFlatSB,MakeDragList,DrawInsert,LBItemFromPt")
duetos_stub_dll(comdlg32 0x101E0000 "GetOpenFileNameA,GetOpenFileNameW,GetSaveFileNameA,GetSaveFileNameW,ChooseColorA,ChooseColorW,ChooseFontA,ChooseFontW,PrintDlgA,PrintDlgW,CommDlgExtendedError,PageSetupDlgA,PageSetupDlgW,FindTextA,FindTextW,ReplaceTextA,ReplaceTextW,GetFileTitleA,GetFileTitleW")
duetos_stub_dll(version 0x101F0000 "GetFileVersionInfoSizeA,GetFileVersionInfoSizeW,GetFileVersionInfoA,GetFileVersionInfoW,VerQueryValueA,VerQueryValueW,GetFileVersionInfoExA,GetFileVersionInfoExW,VerLanguageNameA,VerLanguageNameW,GetFileVersionInfoSizeExA,GetFileVersionInfoSizeExW,VerFindFileA,VerFindFileW,VerInstallFileA,VerInstallFileW")
duetos_stub_dll(setupapi 0x10200000 "SetupDiGetClassDevsA,SetupDiGetClassDevsW,SetupDiDestroyDeviceInfoList,SetupDiEnumDeviceInfo,SetupOpenInfFileA,SetupOpenInfFileW,SetupCloseInfFile,SetupDiGetDeviceRegistryPropertyA,SetupDiGetDeviceRegistryPropertyW,SetupDiGetDeviceInterfaceDetailA,SetupDiGetDeviceInterfaceDetailW,SetupDiEnumDeviceInterfaces,SetupGetLineByIndexA,SetupFindFirstLineA,SetupFindNextLine,SetupDiCreateDeviceInfoList,SetupDiCreateDeviceInfoListExW,SetupDiOpenDeviceInfoA,SetupDiOpenDeviceInfoW,SetupDiBuildClassInfoList,SetupDiClassGuidsFromNameA,SetupDiClassGuidsFromNameW,SetupDiClassNameFromGuidA,SetupDiClassNameFromGuidW,SetupDiOpenDevRegKey,SetupDiOpenClassRegKey,SetupDiOpenClassRegKeyExA,SetupDiOpenClassRegKeyExW,SetupDiCreateDeviceInfoA,SetupDiCreateDeviceInfoW,SetupDiSetDeviceRegistryPropertyA,SetupDiSetDeviceRegistryPropertyW,SetupDiCallClassInstaller,SetupDiInstallDevice,SetupDiInstallClassA,SetupDiInstallClassW,SetupCopyOEMInfA,SetupCopyOEMInfW,SetupUninstallOEMInfA,SetupUninstallOEMInfW,CM_Get_Device_ID_Size,CM_Get_Device_IDA,CM_Get_Device_IDW,CM_Locate_DevNodeA,CM_Locate_DevNodeW")

# Stage-2 slice 33 — six more support DLLs.
duetos_stub_dll(iphlpapi 0x10210000 "GetAdaptersInfo,GetAdaptersAddresses,GetIfTable,GetNumberOfInterfaces,IcmpSendEcho,IcmpCreateFile,IcmpCloseHandle,GetIpForwardTable,GetIpAddrTable,GetTcpTable,GetUdpTable,GetExtendedTcpTable,GetExtendedUdpTable,GetNetworkParams,GetBestRoute,IcmpSendEcho2,Icmp6CreateFile,GetIfEntry,GetIfEntry2,GetIfTable2,GetIfStackTable,FreeMibTable,GetInterfaceInfo,GetBestInterface,GetBestInterfaceEx,NotifyAddrChange,NotifyRouteChange,CancelIPChangeNotify,GetUnicastIpAddressTable,GetUnicastIpAddressEntry,GetIpInterfaceTable,GetIpInterfaceEntry,SetIpInterfaceEntry,SetUnicastIpAddressEntry,CreateUnicastIpAddressEntry,DeleteUnicastIpAddressEntry,GetTcpTable2,GetTcp6Table,GetTcp6Table2,GetUdp6Table,SetTcpEntry,SetIpForwardEntry,CreateIpForwardEntry,DeleteIpForwardEntry,AddIPAddress,DeleteIPAddress,SendARP,GetIpStatistics,GetIpStatisticsEx,GetTcpStatistics,GetUdpStatistics,GetIcmpStatistics,ConvertInterfaceIndexToLuid,ConvertInterfaceLuidToIndex,ConvertInterfaceLuidToNameW,ConvertInterfaceNameToLuidW")
duetos_stub_dll(userenv 0x10220000 "GetUserProfileDirectoryA,GetUserProfileDirectoryW,GetAllUsersProfileDirectoryA,GetAllUsersProfileDirectoryW,GetDefaultUserProfileDirectoryW,GetDefaultUserProfileDirectoryA,GetProfilesDirectoryW,GetProfilesDirectoryA,CreateEnvironmentBlock,DestroyEnvironmentBlock,LoadUserProfileW,UnloadUserProfile,ExpandEnvironmentStringsForUserA,ExpandEnvironmentStringsForUserW,RefreshPolicy,RefreshPolicyEx,EnterCriticalPolicySection,LeaveCriticalPolicySection,GetGPOListW,FreeGPOListW,GetAppliedGPOListW,RegisterGPNotification,UnregisterGPNotification,CreateProfile,DeleteProfileW,GetProfileType")
duetos_stub_dll(wtsapi32 0x10230000 "WTSQuerySessionInformationA,WTSQuerySessionInformationW,WTSFreeMemory,WTSEnumerateSessionsA,WTSEnumerateSessionsW,WTSRegisterSessionNotification,WTSUnRegisterSessionNotification,WTSGetActiveConsoleSessionId,WTSQueryUserToken,WTSEnumerateProcessesA,WTSEnumerateProcessesW,WTSWaitSystemEvent,WTSOpenServerA,WTSOpenServerW,WTSCloseServer,WTSDisconnectSession,WTSLogoffSession,WTSSendMessageA,WTSSendMessageW,ProcessIdToSessionId")
duetos_stub_dll(dwmapi 0x10240000 "DwmIsCompositionEnabled,DwmEnableComposition,DwmExtendFrameIntoClientArea,DwmGetWindowAttribute,DwmSetWindowAttribute,DwmFlush,DwmGetColorizationColor,DwmEnableBlurBehindWindow,DwmRegisterThumbnail,DwmUnregisterThumbnail,DwmInvalidateIconicBitmaps,DwmSetIconicThumbnail,DwmSetIconicLivePreviewBitmap,DwmEnableMMCSS,DwmDefWindowProc,DwmGetTransportAttributes,DwmUpdateThumbnailProperties,DwmShowContact,DwmAttachMilContent,DwmDetachMilContent,DwmGetCompositionTimingInfo,DwmModifyPreviousFrame,DwmTransitionOwnedWindow,DwmGetUnmetTabRequirements,DwmpActivateLivePreview")
duetos_stub_dll(uxtheme 0x10250000 "OpenThemeData,CloseThemeData,IsThemeActive,IsAppThemed,SetWindowTheme,GetThemeSysFont,DrawThemeBackground,DrawThemeText,GetThemeColor,GetThemeMargins,GetThemeFont,GetThemeMetric,GetThemePartSize,GetCurrentThemeName,IsThemePartDefined,EnableThemeDialogTexture,IsThemeDialogTextureEnabled,SetWindowThemeAttribute,GetThemeBitmap,DrawThemeParentBackground,DrawThemeParentBackgroundEx,BufferedPaintInit,BufferedPaintUnInit,BeginBufferedPaint,EndBufferedPaint,BufferedPaintClear,BufferedPaintSetAlpha,GetThemeInt,GetThemeBool,GetThemeRect,GetThemeBackgroundContentRect,GetThemeTextExtent,GetThemeTextMetrics,HitTestThemeBackground,DrawThemeEdge,DrawThemeIcon,GetThemeFilename,GetThemeStream,BeginPanningFeedback,EndPanningFeedback,UpdatePanningFeedback")
duetos_stub_dll(secur32 0x10260000 "AcquireCredentialsHandleA,AcquireCredentialsHandleW,FreeCredentialsHandle,InitializeSecurityContextA,InitializeSecurityContextW,DeleteSecurityContext,GetUserNameExA,GetUserNameExW,AcceptSecurityContext,EnumerateSecurityPackagesA,EnumerateSecurityPackagesW,FreeContextBuffer,QueryContextAttributesA,QueryContextAttributesW,QuerySecurityPackageInfoA,QuerySecurityPackageInfoW,LsaConnectUntrusted,LsaDeregisterLogonProcess,LsaLookupAuthenticationPackage,LsaCallAuthenticationPackage,LsaFreeReturnBuffer,LsaRegisterLogonProcess,LsaLogonUser,TranslateNameA,TranslateNameW,CompleteAuthToken,ImpersonateSecurityContext,RevertSecurityContext,MakeSignature,VerifySignature,EncryptMessage,DecryptMessage")

# DirectX peripheral DLLs v0 — input/audio/2D-blit/Direct2D/DirectWrite.
# Each is a real COM-vtable implementation that satisfies game/runtime
# probes; audio path is silent for now (HDA mixer not wired through).
duetos_stub_dll(dinput8 0x10270000 "DirectInput8Create")
duetos_stub_dll(xinput1_4 0x10280000 "XInputGetState,XInputSetState,XInputGetCapabilities,XInputGetBatteryInformation,XInputGetKeystroke,XInputEnable")
duetos_stub_dll(xaudio2_8 0x10290000 "XAudio2Create,CreateAudioReverb,CreateAudioVolumeMeter")
duetos_stub_dll(dsound 0x102A0000 "DirectSoundCreate,DirectSoundCreate8,DirectSoundEnumerateA,DirectSoundEnumerateW,GetDeviceID")
duetos_stub_dll(ddraw 0x102B0000 "DirectDrawCreate,DirectDrawCreateEx,DirectDrawEnumerateA,DirectDrawEnumerateW")
duetos_stub_dll(d2d1 0x102C0000 "D2D1CreateFactory")
duetos_stub_dll(dwrite 0x102D0000 "DWriteCreateFactory")


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

# DUETOS_GDB_SERVER — wire COM2 to the in-kernel GDB Remote
# Serial Protocol server (kernel/diag/gdb_server.{h,cpp}). When
# ON, int3 (#BP) and #DB in kernel code route to the GDB stop
# loop instead of the existing log-and-continue path; the
# kernel halts until an external debugger attached to QEMU's
# COM2 → tcp::1234 issues `c` / `D` / `k`. When OFF, the
# server stays dormant and int3 is recoverable as before —
# IMPORTANT because a server-wired build with no debugger
# attached would hang on any int3.
#
# Default-ON in the x86_64-debug preset (CMakePresets.json):
# debug builds are dev-loop builds where you might want to
# attach at any moment, so paying the trivial COM2-init cost
# is worth it. Release builds keep it OFF.
option(DUETOS_GDB_SERVER "Wire COM2 to the in-kernel GDB server (live debug via tcp::1234)" OFF)
if(DUETOS_GDB_SERVER)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_GDB_SERVER=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_GDB_SERVER=1)
endif()

# DUETOS_GDB_DEMO — fire `int3` at end of kernel_main so an
# external GDB session can exercise the attach + inspect +
# continue cycle. Implies DUETOS_GDB_SERVER. NOT needed for
# normal use of the GDB server — that just needs DUETOS_GDB_SERVER
# (which the debug preset already turns on). DEMO is the
# "I want a guaranteed stop point so I can test the attach
# plumbing" convenience flag.
option(DUETOS_GDB_DEMO "Fire int3 at end of kernel_main to wait for GDB attach (testing only)" OFF)
if(DUETOS_GDB_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_GDB_DEMO=1 DUETOS_GDB_SERVER=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_GDB_DEMO=1 DUETOS_GDB_SERVER=1)
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

# Link-time optimization (build-flavor follow-up). When ON, every
# kernel TU is built with `-flto=thin` and the link consumes the
# bitcode-flavored .o files via lld's ThinLTO. The two-stage
# symbol-table generation still works because lld emits a real ELF
# for each stage; gen-symbols.sh reads the stage-1 ELF normally.
#
# Costs:
#   - First link is slower (lld walks the bitcode).
#   - Debug info is preserved but optimization may reorder code;
#     for triple-fault chases prefer a non-LTO debug build.
# Wins:
#   - Inlines across TU boundaries that single-TU codegen can't.
#     The klog hot path and the cap-gate hot path benefit visibly
#     on -O2 release.
#
# Wired off the top-level DUETOS_LTO option (declared in the root
# CMakeLists.txt). Applied to both stages so symbol addresses
# remain consistent across the symbol-table generation handoff.
# constexpr step limit. The Win32 thunk table's compile-time
# insertion sort is O(N^2) over ~1200 entries, which exceeds clang's
# default 1M-step constexpr budget. Bump to 20M; cost is purely
# compile-time. If the table grows past ~3000 entries, swap the
# sort for an O(N log N) merge sort instead of bumping further.
target_compile_options(duetos-kernel        PRIVATE -fconstexpr-steps=20000000)
target_compile_options(duetos-kernel-stage1 PRIVATE -fconstexpr-steps=20000000)

if(DUETOS_LTO)
    set(DUETOS_LTO_FLAGS -flto=thin)
    target_compile_options(duetos-kernel        PRIVATE ${DUETOS_LTO_FLAGS})
    target_compile_options(duetos-kernel-stage1 PRIVATE ${DUETOS_LTO_FLAGS})
    target_link_options(duetos-kernel        PRIVATE ${DUETOS_LTO_FLAGS})
    target_link_options(duetos-kernel-stage1 PRIVATE ${DUETOS_LTO_FLAGS})
    message(STATUS "DUETOS_LTO=ON — building kernel with -flto=thin")
endif()

# UBSAN runtime (plan D5 + D5-followup). When ON, every kernel TU
# is built with `-fsanitize=undefined -fno-sanitize-trap=all`. The
# `__ubsan_handle_*` symbols the compiler emits resolve to the
# in-tree runtime in `kernel/diag/ubsan.cpp` — each handler logs
# one structured klog warning + serial line and returns. Use the
# `x86_64-debug-ubsan` preset to enable.
option(DUETOS_ENABLE_UBSAN "Build the kernel with -fsanitize=undefined for UB diagnostics" OFF)
if(DUETOS_ENABLE_UBSAN)
    # `-fno-sanitize=function` suppresses the call-through-mismatched-
    # function-pointer-type check (`__ubsan_handle_function_type_mismatch`).
    # That check uses RTTI metadata the kernel deliberately does not
    # build; with it on, every callback dispatch (sched task entry,
    # IRQ handler, syscall thunk) emits a handler symbol the runtime
    # has no use for and the link fails. The remaining UBSAN classes
    # (signed overflow, OOB, divrem, alignment, …) cover what we want
    # without dragging in the C++-RTTI-shaped CFI surface.
    set(DUETOS_UBSAN_FLAGS -fsanitize=undefined -fno-sanitize=function -fno-sanitize-trap=all)
    target_compile_options(duetos-kernel        PRIVATE ${DUETOS_UBSAN_FLAGS})
    target_compile_options(duetos-kernel-stage1 PRIVATE ${DUETOS_UBSAN_FLAGS})
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_UBSAN=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_UBSAN=1)
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
