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
# Build-info header. The _duetos_git_* / _duetos_build_date vars are
# computed (and sanitised to valid C string literals) by the top-level
# CMakeLists.txt before add_subdirectory(kernel), so they are in scope
# here. configure_file writes them into a FILE on the kernel include
# path — they never reach the compiler command line / a shell, so a
# commit subject with shell metacharacters (`;` etc.) can't break the
# build. util/build_config.h includes the result.
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/duetos_build_info.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/duetos_build_info.h"
    @ONLY)

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

# Rust crates are handled by the kernel/rust aggregate CMake target below.
# Filter out anything that may have leaked into the C++ glob from crate build dirs
# (CMake's binary dir can sit under a crate on some setups).
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^fs/duetfs/(target|cargo-target|duetfs-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/usb/class_rust/(target|cargo-target|usbclass-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/usb/hid_rust/(target|cargo-target|usbhid-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/usb/msc_scsi_rust/(target|cargo-target|msc-scsi-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^net/parsers_rust/(target|cargo-target|net-parsers-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^util/img_meta_rust/(target|cargo-target|img-meta-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^loader/exec_meta_rust/(target|cargo-target|exec-meta-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^fs/ntfs_rust/(target|cargo-target|ntfs-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^fs/exfat_rust/(target|cargo-target|exfat-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^fs/ext4_rust/(target|cargo-target|ext4-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^acpi/acpi_rust/(target|cargo-target|acpi-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^arch/x86_64/smbios_rust/(target|cargo-target|smbios-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/pci/caps_rust/(target|cargo-target|pci-caps-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^mm/multiboot2_rust/(target|cargo-target|multiboot2-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^net/wifi80211_rust/(target|cargo-target|wifi80211-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^net/hci_rust/(target|cargo-target|hci-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^net/tls_rust/(target|cargo-target|tls-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^util/vt_parser_rust/(target|cargo-target|vt-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/gpu/nvidia_gsp_fw_rust/(target|cargo-target|nvidia-gsp-fw-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/gpu/amd_gfx_fw_rust/(target|cargo-target|amd-gfx-fw-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/net/bcm43xx_fw_rust/(target|cargo-target|bcm-fw-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/net/rtl88xx_fw_rust/(target|cargo-target|rtl-fw-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/net/iwlwifi_fw_rust/(target|cargo-target|iwl-fw-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/iommu/dmar_rust/(target|cargo-target|dmar-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^drivers/iommu/ivrs_rust/(target|cargo-target|ivrs-cargo-target)/")
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^rust/(target|cargo-target|duetos-kernel-rust-cargo-target)/")
# AArch64 starter files (boot.S, exceptions.S, context_switch.S,
# usermode.S, syscall_entry.S) — second-tier-pillar surface that
# does not yet build into a runnable kernel. Exclude from the
# x86_64 kernel image; the assemble-verify rule below proves the
# files are valid AArch64 without trying to link a kernel.
list(FILTER DUETOS_KERNEL_SHARED_SOURCES EXCLUDE REGEX "^arch/aarch64/")

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

# Optional firmware staging tree. The installer (or a developer doing a
# hardware bring-up image) can point this at a directory whose contents
# should appear under /lib/firmware in the trusted ramfs. This keeps
# redistributable/vendor firmware out of git while still letting the
# Wi-Fi drivers use the normal VFS firmware-loader path on first boot.
set(DUETOS_FIRMWARE_STAGING_DIR "" CACHE PATH
    "Directory to embed under /lib/firmware for installer-staged Wi-Fi/GPU firmware")
set(DUETOS_FIRMWARE_RAMFS_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build/gen-firmware-ramfs.py")
set(DUETOS_FIRMWARE_RAMFS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_firmware_ramfs.h")
set(_duetos_firmware_deps "")
if(DUETOS_FIRMWARE_STAGING_DIR)
    if(NOT IS_DIRECTORY "${DUETOS_FIRMWARE_STAGING_DIR}")
        message(FATAL_ERROR
            "DUETOS_FIRMWARE_STAGING_DIR is set but is not a directory: ${DUETOS_FIRMWARE_STAGING_DIR}")
    endif()
    file(GLOB_RECURSE _duetos_firmware_deps CONFIGURE_DEPENDS
        "${DUETOS_FIRMWARE_STAGING_DIR}/*")
    message(STATUS "Installer firmware staging : ${DUETOS_FIRMWARE_STAGING_DIR}")
else()
    message(STATUS "Installer firmware staging : <empty>")
endif()
add_custom_command(
    OUTPUT "${DUETOS_FIRMWARE_RAMFS_HEADER}"
    COMMAND python3 "${DUETOS_FIRMWARE_RAMFS_SCRIPT}"
            "${DUETOS_FIRMWARE_STAGING_DIR}" "${DUETOS_FIRMWARE_RAMFS_HEADER}"
    DEPENDS "${DUETOS_FIRMWARE_RAMFS_SCRIPT}" ${_duetos_firmware_deps}
    COMMENT "Generating installer-staged /lib/firmware ramfs tree"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_FIRMWARE_RAMFS_HEADER}")

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
        "${CMAKE_SOURCE_DIR}/userland/libc/src/string.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/setjmp.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/duet/syscall.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/duet/socket.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/string.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/setjmp.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/unistd.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/usershell.lds"
    COMMENT     "Compiling + embedding /bin/usershell.elf (real userland shell)")

# Helper: register a portable native ELF app from
# `userland/native-apps/<name>/<name>.c`. Compiles via
# tools/build/build-native-app.sh, links against the userland
# libc, embeds the bytes via embed-blob.py. Output header lives
# at ${CMAKE_CURRENT_BINARY_DIR}/generated_<name>_native.h and
# exposes `kBin<Name>NativeBytes` in `duetos::fs::generated`.
#
# Used for every new portable native app — see
# `wiki/tooling/Native-Apps.md` for the migration plan that
# moves the in-kernel apps under `kernel/apps/` out via the
# same helper.
function(duetos_native_app app_name)
    set(_header "${CMAKE_CURRENT_BINARY_DIR}/generated_${app_name}_native.h")
    set(_script "${CMAKE_SOURCE_DIR}/tools/build/build-native-app.sh")
    set(_app_src "${CMAKE_SOURCE_DIR}/userland/native-apps/${app_name}/${app_name}.c")
    set(_libc_deps
        "${CMAKE_SOURCE_DIR}/userland/libc/src/crt0.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/syscall.c"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/string.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/setjmp.S"
        "${CMAKE_SOURCE_DIR}/userland/libc/src/stdio.c"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/duet/syscall.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/duet/socket.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/string.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/setjmp.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/stdio.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/include/unistd.h"
        "${CMAKE_SOURCE_DIR}/userland/libc/usershell.lds")
    add_custom_command(
        OUTPUT  "${_header}"
        COMMAND "${_script}" "${CMAKE_SOURCE_DIR}" "${_header}" "${app_name}"
        DEPENDS "${_app_src}" "${_script}" "${DUETOS_EMBED_BLOB_SCRIPT}" ${_libc_deps}
        COMMENT "Building + embedding portable native app /bin/${app_name}"
        VERBATIM)
    set(DUETOS_KERNEL_SHARED_SOURCES
        ${DUETOS_KERNEL_SHARED_SOURCES} "${_header}"
        PARENT_SCOPE)
endfunction()

duetos_native_app(hello_native)
duetos_native_app(nat_calc)
duetos_native_app(nat_sysinfo)
duetos_native_app(duet-pkg)
duetos_native_app(netd)
duetos_native_app(netd_probe)

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

# ----------------------------------------------------------------------------
# UEFI loader bytes — embed BOOTX64.EFI into the kernel image so the
# disk installer can copy it onto the freshly-formatted ESP. Same
# embed pattern as windows-kill above; depends on the duetos-uefi
# target output set by add_subdirectory(boot/uefi). DUETOS_UEFI_EFI
# is cached by boot/uefi/CMakeLists.txt; that subdirectory is
# processed before this one (see CMakeLists.txt at the repo root).
# ----------------------------------------------------------------------------
set(DUETOS_BOOTX64_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_bootx64_efi.h")
add_custom_command(
    OUTPUT "${DUETOS_BOOTX64_HEADER}"
    COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_UEFI_EFI}" "${DUETOS_BOOTX64_HEADER}"
            kBinBootX64EfiBytes --namespace "duetos::fs::generated"
    DEPENDS "${DUETOS_UEFI_EFI}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding UEFI loader BOOTX64.EFI for the disk installer"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_BOOTX64_HEADER}")

# Source-built Win32 smoke PE fixtures. These used to be checked-in
# .exe files; keep them generated in the build tree so PRs do not carry
# rebuilt executable artifacts. The helper script still supports manual
# in-tree rebuilds, but CMake always drives it with --out-dir.
#
# Toolchain dependency: build-smokes.sh requires `x86_64-w64-mingw32-gcc`
# (the Win32 cross-compiler). If it's not on the host we degrade
# gracefully — the build still succeeds, each smoke PE header is
# emitted as a `_len = 0` stub via embed-blob.py's `--empty` mode,
# and the kernel's `SpawnPeFile` skips zero-length blobs at boot.
# This mirrors the duetos-iso pattern: missing optional tooling
# disables a feature with a clear status message rather than
# breaking the kernel build.
find_program(MINGW_W64_GCC x86_64-w64-mingw32-gcc)
set(DUETOS_SMOKE_PE_BUILD_SCRIPT "${CMAKE_SOURCE_DIR}/userland/apps/build-smokes.sh")
set(DUETOS_SMOKE_PE_BUILD_DIR    "${CMAKE_CURRENT_BINARY_DIR}/smoke-pes")
set(DUETOS_SMOKE_PE_STAMP        "${DUETOS_SMOKE_PE_BUILD_DIR}/.stamp")
if(MINGW_W64_GCC)
    file(GLOB_RECURSE DUETOS_SMOKE_PE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/userland/apps/*.c")
    add_custom_command(
        OUTPUT "${DUETOS_SMOKE_PE_STAMP}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${DUETOS_SMOKE_PE_BUILD_DIR}"
        COMMAND "${DUETOS_SMOKE_PE_BUILD_SCRIPT}" --out-dir "${DUETOS_SMOKE_PE_BUILD_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E touch "${DUETOS_SMOKE_PE_STAMP}"
        DEPENDS "${DUETOS_SMOKE_PE_BUILD_SCRIPT}" ${DUETOS_SMOKE_PE_SOURCES}
        COMMENT "Compiling source-built Win32 smoke PE fixtures"
        VERBATIM)
else()
    # No mingw cross-compiler: emit an empty stamp so the embed
    # step still has a dependency it can satisfy, and let each
    # `duetos_embed_smoke_pe` call route through embed-blob.py
    # `--empty` (see below).
    add_custom_command(
        OUTPUT "${DUETOS_SMOKE_PE_STAMP}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${DUETOS_SMOKE_PE_BUILD_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E touch "${DUETOS_SMOKE_PE_STAMP}"
        COMMENT "Skipping Win32 smoke PE compilation (x86_64-w64-mingw32-gcc not found)"
        VERBATIM)
    message(STATUS "Win32 smoke PE fixtures disabled (x86_64-w64-mingw32-gcc not found).")
    message(STATUS "  Install with: sudo apt-get install -y gcc-mingw-w64-x86-64")
    message(STATUS "  The kernel will still build; smoke PE blobs are emitted as _len=0 stubs.")
    message(STATUS "  After installing, re-run cmake configure (or rebuild with --fresh) to pick it up.")
endif()
add_custom_target(duetos-smoke-pes DEPENDS "${DUETOS_SMOKE_PE_STAMP}")

# mini_browser.exe — minimal WinSock 2 PE that does an HTTP/1.0 GET to
# www.google.com. Source is userland/apps/mini_browser/browser.c and
# CMake now embeds the build-tree PE produced by build-smokes.sh.
# (Stubbed to a zero-length blob when MINGW_W64_GCC is missing — see
# the smoke-PE gate above.)
set(DUETOS_MINIBROWSER_SRC    "${DUETOS_SMOKE_PE_BUILD_DIR}/mini_browser/browser.exe")
set(DUETOS_MINIBROWSER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_minibrowser_pe.h")
if(MINGW_W64_GCC)
    add_custom_command(
        OUTPUT "${DUETOS_MINIBROWSER_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${DUETOS_MINIBROWSER_SRC}" "${DUETOS_MINIBROWSER_HEADER}"
                kBinMiniBrowserBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_SMOKE_PE_STAMP}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding mini_browser PE /bin/mini_browser.exe"
        VERBATIM)
else()
    add_custom_command(
        OUTPUT "${DUETOS_MINIBROWSER_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}" --empty
                "${DUETOS_MINIBROWSER_HEADER}"
                kBinMiniBrowserBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Emitting mini_browser PE stub (mingw absent)"
        VERBATIM)
endif()
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_MINIBROWSER_HEADER}")

# pe32_smoke.exe — minimal PE32 (i386) test image. Built with the
# i686 mingw cross compiler so the PE has Machine=0x014C +
# OptHdrMagic=0x10B. Today the loader's MapAndRun rejects it with
# `PeStatus::Pe32ExecutionNotReady`; once 32-bit DLL preload + IAT-32
# walker land, it'll run end-to-end via EnterUserMode32.
find_program(MINGW_W64_I686_GCC i686-w64-mingw32-gcc)
set(DUETOS_PE32_SMOKE_SRC "${CMAKE_SOURCE_DIR}/userland/apps/pe32_smoke/pe32_smoke.c")
set(DUETOS_PE32_SMOKE_EXE "${CMAKE_CURRENT_BINARY_DIR}/pe32_smoke.exe")
set(DUETOS_PE32_SMOKE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_pe32_smoke_pe.h")
if(MINGW_W64_I686_GCC)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_SMOKE_EXE}"
        COMMAND "${MINGW_W64_I686_GCC}"
                -nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe
                -e _mainCRTStartup -Wl,--subsystem,console -Wl,--entry,_mainCRTStartup
                -o "${DUETOS_PE32_SMOKE_EXE}" "${DUETOS_PE32_SMOKE_SRC}" -lkernel32
        DEPENDS "${DUETOS_PE32_SMOKE_SRC}"
        COMMENT "Cross-compiling pe32_smoke.exe (i386 PE32)"
        VERBATIM)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_SMOKE_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${DUETOS_PE32_SMOKE_EXE}" "${DUETOS_PE32_SMOKE_HEADER}"
                kBinPe32SmokeBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_PE32_SMOKE_EXE}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding pe32_smoke PE"
        VERBATIM)
else()
    add_custom_command(
        OUTPUT "${DUETOS_PE32_SMOKE_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}" --empty
                "${DUETOS_PE32_SMOKE_HEADER}"
                kBinPe32SmokeBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Emitting pe32_smoke PE stub (i686 mingw absent)"
        VERBATIM)
    message(STATUS "PE32 smoke fixture disabled (i686-w64-mingw32-gcc not found).")
    message(STATUS "  Install with: sudo apt-get install -y gcc-mingw-w64-i686")
endif()
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_PE32_SMOKE_HEADER}")

# pe32_rich.exe — PE32 test that imports one or two functions from
# each of the 13 preloaded i386 DLLs. Verifies the full via-DLL IAT
# resolution chain end-to-end. Built the same way as pe32_smoke.
set(DUETOS_PE32_RICH_SRC "${CMAKE_SOURCE_DIR}/userland/apps/pe32_rich/pe32_rich.c")
set(DUETOS_PE32_RICH_EXE "${CMAKE_CURRENT_BINARY_DIR}/pe32_rich.exe")
set(DUETOS_PE32_RICH_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_pe32_rich_pe.h")
if(MINGW_W64_I686_GCC)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_RICH_EXE}"
        COMMAND "${MINGW_W64_I686_GCC}"
                -nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe
                -e _mainCRTStartup -Wl,--subsystem,console -Wl,--entry,_mainCRTStartup
                -o "${DUETOS_PE32_RICH_EXE}" "${DUETOS_PE32_RICH_SRC}"
                -lkernel32 -lmsvcrt -luser32 -lgdi32 -ladvapi32
                -lcomctl32 -lcomdlg32 -lcrypt32 -liphlpapi
                -lshell32 -lshlwapi -lws2_32 -lbcrypt
        DEPENDS "${DUETOS_PE32_RICH_SRC}"
        COMMENT "Cross-compiling pe32_rich.exe (i386 PE32 with 13-DLL imports)"
        VERBATIM)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_RICH_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${DUETOS_PE32_RICH_EXE}" "${DUETOS_PE32_RICH_HEADER}"
                kBinPe32RichBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_PE32_RICH_EXE}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding pe32_rich PE"
        VERBATIM)
else()
    add_custom_command(
        OUTPUT "${DUETOS_PE32_RICH_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}" --empty
                "${DUETOS_PE32_RICH_HEADER}"
                kBinPe32RichBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Emitting pe32_rich PE stub (i686 mingw absent)"
        VERBATIM)
endif()
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_PE32_RICH_HEADER}")

# pe32_miss.exe — PE32 that calls an unresolved Win32 import to
# validate the 32-bit Win32 thunks page. The import (user32!
# SetWindowsHookExA) is NOT in our v0 user32_32 stubs, so the
# ResolveImports catch-all routes the IAT slot to
# kWin32Thunks32UnresolvedVa. The stub does SYS_EXIT(0xDEAD0042)
# and the process destroys cleanly.
set(DUETOS_PE32_MISS_SRC "${CMAKE_SOURCE_DIR}/userland/apps/pe32_miss/pe32_miss.c")
set(DUETOS_PE32_MISS_EXE "${CMAKE_CURRENT_BINARY_DIR}/pe32_miss.exe")
set(DUETOS_PE32_MISS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_pe32_miss_pe.h")
if(MINGW_W64_I686_GCC)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_MISS_EXE}"
        COMMAND "${MINGW_W64_I686_GCC}"
                -nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe
                -e _mainCRTStartup -Wl,--subsystem,console -Wl,--entry,_mainCRTStartup
                -o "${DUETOS_PE32_MISS_EXE}" "${DUETOS_PE32_MISS_SRC}"
                -lkernel32 -luser32
        DEPENDS "${DUETOS_PE32_MISS_SRC}"
        COMMENT "Cross-compiling pe32_miss.exe (PE32 calling unresolved import)"
        VERBATIM)
    add_custom_command(
        OUTPUT "${DUETOS_PE32_MISS_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                "${DUETOS_PE32_MISS_EXE}" "${DUETOS_PE32_MISS_HEADER}"
                kBinPe32MissBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_PE32_MISS_EXE}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Embedding pe32_miss PE"
        VERBATIM)
else()
    add_custom_command(
        OUTPUT "${DUETOS_PE32_MISS_HEADER}"
        COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}" --empty
                "${DUETOS_PE32_MISS_HEADER}"
                kBinPe32MissBytes --namespace "duetos::fs::generated"
        DEPENDS "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Emitting pe32_miss PE stub (i686 mingw absent)"
        VERBATIM)
endif()
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_PE32_MISS_HEADER}")

# Surface-coverage PE smoke apps. Each one is a self-contained
# console PE (~10 KB) targeting a single Win32 API surface. Source
# lives in userland/apps/<name>/<name>.c; CMake embeds build-tree
# outputs so generated .exe files stay out of git.
#
# Branch on MINGW_W64_GCC: with mingw present, embed the real .exe;
# without, route through embed-blob.py `--empty` so the kernel builds
# without the cross-compiler. The kernel's SpawnPeFile checks
# `pe_len == 0` and skips, so missing fixtures don't break boot.
function(duetos_embed_smoke_pe app_name symbol)
    set(_src "${DUETOS_SMOKE_PE_BUILD_DIR}/${app_name}/${app_name}.exe")
    set(_hdr "${CMAKE_CURRENT_BINARY_DIR}/generated_${app_name}_pe.h")
    if(MINGW_W64_GCC)
        add_custom_command(
            OUTPUT "${_hdr}"
            COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
                    "${_src}" "${_hdr}"
                    "${symbol}" --namespace "duetos::fs::generated"
            DEPENDS "${DUETOS_SMOKE_PE_STAMP}" "${DUETOS_EMBED_BLOB_SCRIPT}"
            COMMENT "Embedding ${app_name} PE"
            VERBATIM)
    else()
        add_custom_command(
            OUTPUT "${_hdr}"
            COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}" --empty
                    "${_hdr}"
                    "${symbol}" --namespace "duetos::fs::generated"
            DEPENDS "${DUETOS_EMBED_BLOB_SCRIPT}"
            COMMENT "Emitting ${app_name} PE stub (mingw absent)"
            VERBATIM)
    endif()
    set(DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_KERNEL_SHARED_SOURCES}" "${_hdr}" PARENT_SCOPE)
endfunction()

duetos_embed_smoke_pe(crypto_smoke   kBinCryptoSmokeBytes)
duetos_embed_smoke_pe(paths_smoke    kBinPathsSmokeBytes)
duetos_embed_smoke_pe(time_smoke     kBinTimeSmokeBytes)
duetos_embed_smoke_pe(wininet_smoke  kBinWininetSmokeBytes)
duetos_embed_smoke_pe(browser_pe     kBinBrowserPeBytes)
duetos_embed_smoke_pe(tls_pe         kBinTlsPeBytes)
duetos_embed_smoke_pe(seh_pe         kBinSehPeBytes)
duetos_embed_smoke_pe(sync_smoke     kBinSyncSmokeBytes)
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
duetos_embed_smoke_pe(pe_stress      kBinPeStressBytes)
duetos_embed_smoke_pe(net_loopback_smoke kBinNetLoopbackSmokeBytes)
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

# Chrome font Bold — Liberation Sans Bold (SIL OFL 1.1). Pass C
# typography hierarchy needs a bold weight for Display / Title roles
# and for Bold-flagged Body / Caption draws. Embedded as bytes via
# the same embed-blob.py path as the Regular variant; boot wires it
# through TtfLoad + TtfChromeBoldSet so ChromeTextDraw can pick the
# matching face when ChromeTextWeight::Bold is requested.
set(DUETOS_CHROME_FONT_BOLD_SRC    "${CMAKE_SOURCE_DIR}/userland/assets/fonts/duet-chrome-bold.ttf")
set(DUETOS_CHROME_FONT_BOLD_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font_bold.h")
add_custom_command(
    OUTPUT "${DUETOS_CHROME_FONT_BOLD_HEADER}"
    COMMAND python3 "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_CHROME_FONT_BOLD_SRC}" "${DUETOS_CHROME_FONT_BOLD_HEADER}"
            kBinChromeFontBoldBytes --namespace "duetos::drivers::video::generated"
    DEPENDS "${DUETOS_CHROME_FONT_BOLD_SRC}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding chrome font Liberation Sans Bold (SIL OFL 1.1)"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_CHROME_FONT_BOLD_HEADER}")

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

# Shadow corner atlas — 32x32 quadratic falloff baked at configure time.
# Consumed by kernel/drivers/video/shadow.cpp (RenderSoftShadow 9-slice).
set(_shadow_atlas_header "${CMAKE_CURRENT_BINARY_DIR}/generated_shadow_atlas.h")
add_custom_command(
    OUTPUT "${_shadow_atlas_header}"
    COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/build/gen_shadow_atlas.py" "${_shadow_atlas_header}"
    DEPENDS "${CMAKE_SOURCE_DIR}/tools/build/gen_shadow_atlas.py"
    COMMENT "Baking shadow atlas (32x32 quadratic falloff)"
    VERBATIM)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_shadow_atlas_header}")

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
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_internal.h"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_interlocked.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_strmem.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_env.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_locale.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_io.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_sync.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_fs.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32_psapi.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/seh_capture.S"
    COMMENT "Compiling + embedding kernel32.dll (split into per-domain TUs)")

# 32-bit kernel32 companion — PE32 (i386) DLL, preloaded into PE32
# processes' address spaces so their IAT entries to KERNEL32.dll
# resolve. Layer 4 of 32-bit PE support.
duetos_embed_blob(generated_kernel32_32_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-kernel32-32-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/kernel32_32/kernel32_32.c"
    COMMENT "Compiling + embedding kernel32_32.dll (i386 PE32 companion)")

# 32-bit msvcrt companion — string / memory / CRT-startup intrinsics
# every MSVC-built PE32 calls during boot.
duetos_embed_blob(generated_msvcrt_32_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-msvcrt-32-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt_32/msvcrt_32.c"
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt_32/msvcrt_32.def"
        "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt_32/chkstk.S"
    COMMENT "Compiling + embedding msvcrt_32.dll (i386 PE32 companion)")

# Linux vDSO blob — one executable page mapped into every Linux
# ELF process. Currently exports __kernel_rt_sigreturn at offset
# 0 so the signal-delivery path has a fallback restorer when the
# caller's sigaction omits SA_RESTORER. See
# kernel/subsystems/linux/vdso/vdso.S for the full layout.
duetos_embed_blob(generated_linux_vdso.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-linux-vdso.sh"
    SRC     "${CMAKE_SOURCE_DIR}/kernel/subsystems/linux/vdso/vdso.S"
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/kernel/subsystems/linux/vdso/vdso.lds"
    COMMENT "Assembling + embedding Linux vDSO blob (rt_sigreturn trampoline)")

# 32-bit stub DLLs. Each takes (dll_name, base_va, symbol_name) and
# produces a PE32 (i386) DLL whose Export Name field matches the
# i386 importer's descriptor. The bodies are safe-ignore stubs;
# real implementations land slice-by-slice as Layer 4 grows.
macro(duetos_embed_32bit_stub_dll name base_va symbol)
    set(_src "${CMAKE_SOURCE_DIR}/userland/libs/${name}_32/${name}_32.c")
    set(_def "${CMAKE_SOURCE_DIR}/userland/libs/${name}_32/${name}_32.def")
    set(_hdr "${CMAKE_CURRENT_BINARY_DIR}/generated_${name}_32_dll.h")
    add_custom_command(
        OUTPUT "${_hdr}"
        COMMAND "${CMAKE_SOURCE_DIR}/tools/build/build-stub-32-dll.sh"
                "${CMAKE_SOURCE_DIR}" "${_hdr}" "${name}" "${base_va}" "${symbol}"
        DEPENDS "${_src}" "${_def}"
                "${CMAKE_SOURCE_DIR}/tools/build/build-stub-32-dll.sh"
                "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Compiling + embedding ${name}_32.dll (i386 PE32 stub DLL)"
        VERBATIM)
    list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_hdr}")
endmacro()

duetos_embed_32bit_stub_dll(user32   0x10060000 kBinUser32_32DllBytes)
duetos_embed_32bit_stub_dll(gdi32    0x10080000 kBinGdi32_32DllBytes)
duetos_embed_32bit_stub_dll(advapi32 0x100A0000 kBinAdvapi32_32DllBytes)
duetos_embed_32bit_stub_dll(comctl32 0x100C0000 kBinComctl32_32DllBytes)
duetos_embed_32bit_stub_dll(comdlg32 0x100D0000 kBinComdlg32_32DllBytes)
duetos_embed_32bit_stub_dll(crypt32  0x100E0000 kBinCrypt32_32DllBytes)
duetos_embed_32bit_stub_dll(iphlpapi 0x100F0000 kBinIphlpapi_32DllBytes)
duetos_embed_32bit_stub_dll(shell32  0x10110000 kBinShell32_32DllBytes)
duetos_embed_32bit_stub_dll(shlwapi  0x10130000 kBinShlwapi_32DllBytes)
duetos_embed_32bit_stub_dll(ws2_32   0x10150000 kBinWs2_32_32DllBytes)
duetos_embed_32bit_stub_dll(bcrypt   0x10170000 kBinBcrypt_32DllBytes)

duetos_embed_blob(generated_vcruntime140_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-vcruntime140-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/vcruntime140.c"
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/chkstk.S"
        "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/guard_icall.S"
        "${CMAKE_CURRENT_BINARY_DIR}/generated_ntdll_dll.h"
    COMMENT "Compiling + embedding vcruntime140.dll (C++ EH personality + memops; links ntdll.lib)")

duetos_embed_blob(generated_msvcrt_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-msvcrt-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt/msvcrt.c"
    COMMENT "Compiling + embedding msvcrt.dll (string intrinsics retirement)")

duetos_embed_blob(generated_ntdll_dll.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-ntdll-dll.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll.c"
    EXTRA_DEPS
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_internal.h"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_rtl.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_seh.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_dispatch.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_reg.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_info.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_facades.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_token.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll_bulk.c"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/chkstk.S"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/seh_trampolines.S"
        "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ki_user_dispatchers.S"
    COMMENT "Compiling + embedding ntdll.dll (split into per-domain TUs)")

# seh_try_pe.exe — real MSVC __try/__except/__finally over CPU
# faults, built with clang-windows-msvc -fasync-exceptions and
# linked against our own kernel32.lib / ntdll.lib import libs (the
# mingw smoke toolchain can't express MSVC __try in C). Depends on
# the kernel32 + ntdll embed outputs so their .lib files exist.
duetos_embed_blob(generated_seh_try_pe.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-seh-try-pe.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/seh_try_pe/seh_try_pe.c"
    EXTRA_DEPS
        "${CMAKE_CURRENT_BINARY_DIR}/generated_kernel32_dll.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated_ntdll_dll.h"
    COMMENT "Compiling + embedding seh_try_pe.exe (clang-windows __try/__except)")

# cxxeh_pe.exe — real MSVC C++ throw/catch (clang-windows-msvc,
# exceptions on). Exercises vcruntime140's __CxxFrameHandler3 +
# _CxxThrowException over the ntdll two-pass engine. Depends on the
# kernel32 + ntdll + vcruntime140 embeds so their .lib import libs
# exist (the C++ EH personality/throw resolve to vcruntime140).
duetos_embed_blob(generated_cxxeh_pe.h
    SCRIPT  "${CMAKE_SOURCE_DIR}/tools/build/build-cxxeh-pe.sh"
    SRC     "${CMAKE_SOURCE_DIR}/userland/apps/cxxeh_pe/cxxeh_pe.cpp"
    EXTRA_DEPS
        "${CMAKE_CURRENT_BINARY_DIR}/generated_kernel32_dll.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated_ntdll_dll.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated_vcruntime140_dll.h"
    COMMENT "Compiling + embedding cxxeh_pe.exe (clang-windows C++ throw/catch)")

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
    # Optional 4th positional arg: a different basename for the
    # embedded DLL file (overrides the default "${name}.dll").
    # Lets a directory like vulkan_1/ produce vulkan-1.dll
    # so the PE loader sees the canonical Windows import name.
    set(_extra_args "")
    if(${ARGC} GREATER 3)
        set(_extra_args "${ARGV3}")
    endif()
    add_custom_command(
        OUTPUT "${_header}"
        COMMAND "${DUETOS_STUB_DLL_SCRIPT}"
                "${CMAKE_SOURCE_DIR}" "${_header}" "${name}" "${base_va}" "${exports}" ${_extra_args}
        DEPENDS "${_src}" "${DUETOS_STUB_DLL_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Compiling + embedding ${name}.dll"
        VERBATIM
    )
    list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_header}")
endmacro()

duetos_stub_dll(shlwapi 0x100B0000 "PathAddBackslashA,PathAddBackslashW,PathAppendW,PathCombineW,PathFileExistsA,PathFileExistsW,PathFindExtensionA,PathFindExtensionW,PathFindFileNameA,PathFindFileNameW,PathIsDirectoryW,PathRemoveFileSpecW,PathStripPathW,PathRemoveBackslashA,PathRemoveBackslashW,PathRemoveExtensionA,PathRemoveExtensionW,StrCmpA,StrCmpNA,StrCmpW,StrCmpNW,StrCmpIA,StrCmpIW,StrCmpNIA,StrCmpNIW,StrChrA,StrChrW,StrRChrA,StrRChrW,StrStrA,StrStrW,StrStrIA,StrStrIW,PathCanonicalizeW,PathRenameExtensionW,PathIsRelativeA,PathIsRelativeW,PathQuoteSpacesW,PathUnquoteSpacesW,PathMatchSpecW")
duetos_stub_dll(shell32 0x100C0000 "CommandLineToArgvW,ExtractIconW,ExtractIconExW,SHCreateDirectoryW,SHCreateDirectoryExW,SHFileOperationW,SHGetFolderPathA,SHGetFolderPathW,SHGetKnownFolderPath,SHGetPathFromIDListW,SHGetSpecialFolderPathW,ShellExecuteW,ShellExecuteExW,ShellAboutW,ShellAboutA")
duetos_stub_dll(ole32 0x100D0000 "CoInitialize,CoInitializeEx,CoUninitialize,CoInitializeSecurity,CoSetProxyBlanket,OleInitialize,OleUninitialize,CoCreateInstance,CoCreateInstanceEx,CoGetClassObject,CoGetMalloc,CLSIDFromString,CLSIDFromProgID,IIDFromString,StringFromCLSID,StringFromGUID2,CoTaskMemAlloc,CoTaskMemFree,CoTaskMemRealloc,CoRegisterClassObject,CoRevokeClassObject,CoResumeClassObjects,CoSuspendClassObjects,CoAddRefServerProcess,CoReleaseServerProcess,CreateStreamOnHGlobal,GetHGlobalFromStream,GetRunningObjectTable,RegisterDragDrop,RevokeDragDrop")
duetos_stub_dll(oleaut32 0x100E0000 "VariantInit,VariantClear,VariantCopy,SysAllocString,SysAllocStringLen,SysAllocStringByteLen,SysReAllocString,SysFreeString,SysStringLen,SysStringByteLen")
duetos_stub_dll(winmm 0x100F0000 "timeGetTime,timeBeginPeriod,timeEndPeriod,timeGetDevCaps,timeSetEvent,timeKillEvent,PlaySoundW,mciSendStringW")
duetos_stub_dll(bcrypt 0x10100000 "BCryptOpenAlgorithmProvider,BCryptCloseAlgorithmProvider,BCryptCreateHash,BCryptHashData,BCryptFinishHash,BCryptDestroyHash,BCryptGetProperty,BCryptSetProperty,BCryptGenRandom,BCryptGenerateSymmetricKey,BCryptDestroyKey,BCryptEncrypt,BCryptDecrypt")
duetos_stub_dll(psapi 0x10110000 "EnumProcesses,EnumProcessModules,GetMappedFileNameW,GetModuleBaseNameW,GetModuleFileNameExW,GetProcessImageFileNameW,GetProcessImageFileNameA,GetProcessMemoryInfo,QueryWorkingSet,K32EnumProcesses,K32EnumProcessModules,K32EnumProcessModulesEx,K32GetMappedFileNameW,K32GetModuleBaseNameW,K32GetModuleFileNameExW,K32GetProcessImageFileNameW,K32GetProcessImageFileNameA,K32GetProcessMemoryInfo,K32QueryWorkingSet,GetPerformanceInfo,K32GetPerformanceInfo,EmptyWorkingSet,K32EmptyWorkingSet,GetWsChanges,K32GetWsChanges,InitializeProcessForWsWatch,K32InitializeProcessForWsWatch,GetModuleInformation,K32GetModuleInformation,EnumDeviceDrivers,K32EnumDeviceDrivers,GetDeviceDriverBaseNameA,GetDeviceDriverBaseNameW,K32GetDeviceDriverBaseNameA,K32GetDeviceDriverBaseNameW,GetDeviceDriverFileNameA,GetDeviceDriverFileNameW,QueryFullProcessImageNameA,QueryFullProcessImageNameW,GetMappedFileNameA,K32GetMappedFileNameA,GetModuleBaseNameA,K32GetModuleBaseNameA,GetModuleFileNameExA,K32GetModuleFileNameExA")

# DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs that produce working
# Clear-and-Present pipelines via SYS_GDI_BITBLT.
duetos_stub_dll(d3d9 0x10120000 "Direct3DCreate9,Direct3DCreate9Ex,DuetOS_D3D9_PeekBackBuffer")
duetos_stub_dll(d3d11 0x10130000 "D3D11CreateDevice,D3D11CreateDeviceAndSwapChain,DuetOS_D3D11_PeekBufferMapType")
duetos_stub_dll(d3d12 0x10140000 "D3D12CreateDevice,D3D12GetDebugInterface,D3D12SerializeRootSignature,DuetOS_D3D12_PeekResourceState,DuetOS_D3D12_PeekBarrierMismatchCount")
duetos_stub_dll(dxgi 0x10150000 "CreateDXGIFactory,CreateDXGIFactory1,CreateDXGIFactory2,DXGIGetDebugInterface,DXGIGetDebugInterface1,DXGIDeclareAdapterRemovalSupport")
duetos_stub_dll(user32 0x10160000 "BeginPaint,Beep,CallWindowProcA,CallWindowProcW,CharLowerA,CharLowerW,CharUpperA,CharUpperW,IsCharAlphaA,IsCharAlphaNumericA,IsCharAlphaW,IsCharAlphaNumericW,ClientToScreen,ClipCursor,CloseClipboard,CreateCaret,CreateWindowExA,CreateWindowExW,DefWindowProcA,DefWindowProcW,DestroyCaret,DestroyWindow,DispatchMessageA,DispatchMessageW,EmptyClipboard,EndPaint,EnumWindows,FindWindowA,FindWindowExA,FindWindowExW,FindWindowW,GetActiveWindow,GetAsyncKeyState,GetCapture,GetCaretBlinkTime,GetClientRect,GetClipboardData,GetCursorPos,GetDesktopWindow,GetFocus,GetForegroundWindow,GetKeyState,GetMessageA,GetMessageW,GetParent,GetProcessWindowStation,GetSysColor,GetSystemMetrics,GetWindow,GetWindowLongA,GetWindowLongPtrA,GetWindowLongPtrW,GetWindowLongW,GetWindowRect,GetWindowTextA,GetWindowTextW,HideCaret,InvalidateRect,IsWindow,KillTimer,LoadAcceleratorsA,LoadAcceleratorsW,LoadBitmapA,LoadBitmapW,LoadCursorA,LoadCursorW,LoadIconA,LoadIconW,LoadImageA,LoadImageW,LoadMenuA,LoadMenuW,LoadStringA,LoadStringW,MessageBeep,MessageBoxA,MessageBoxExA,MessageBoxExW,MessageBoxW,MoveWindow,OpenClipboard,PeekMessageA,PeekMessageW,PostMessageA,PostMessageW,PostQuitMessage,PostThreadMessageA,PostThreadMessageW,RegisterClassA,RegisterClassExA,RegisterClassExW,RegisterClassW,ReleaseCapture,ScreenToClient,SendMessageA,SendMessageW,SendNotifyMessageA,SendNotifyMessageW,SetActiveWindow,SetCapture,SetCaretBlinkTime,SetCaretPos,SetClipboardData,SetCursor,SetCursorPos,SetFocus,SetForegroundWindow,SetParent,SetTimer,SetWindowLongA,SetWindowLongPtrA,SetWindowLongPtrW,SetWindowLongW,SetWindowPos,SetWindowTextA,SetWindowTextW,ShowCaret,ShowCursor,ShowWindow,TranslateAcceleratorA,TranslateAcceleratorW,TranslateMessage,UnregisterClassA,UnregisterClassW,UpdateWindow,ValidateRect,EnumDisplayMonitors,MonitorFromPoint,MonitorFromWindow,GetMonitorInfoW,EnumDisplayDevicesW,EnumDisplaySettingsW,DdeInitializeA,DdeInitializeW,DdeUninitialize,DdeCreateStringHandleA,DdeCreateStringHandleW,DdeFreeStringHandle,GetClassInfoW,GetClassInfoExW,CreateAcceleratorTableW,CopyAcceleratorTableW,DestroyAcceleratorTable,GetDpiForSystem,GetDpiForWindow")
duetos_stub_dll(gdi32 0x10180000 "BitBlt,CreateBitmap,CreateBrushIndirect,CreateCompatibleBitmap,CreateCompatibleDC,CreateDIBSection,CreateDIBitmap,CreateFontA,CreateFontIndirectA,CreateFontIndirectW,CreateFontW,CreatePen,CreateSolidBrush,DeleteDC,DeleteObject,DrawTextA,DrawTextW,Ellipse,ExtTextOutA,ExtTextOutW,FillRect,FrameRect,GetDC,GetObjectA,GetObjectW,GetPixel,GetStockObject,GetWindowDC,LineTo,MoveToEx,Polygon,Polyline,Rectangle,ReleaseDC,RestoreDC,SaveDC,SelectObject,SetBkColor,SetBkMode,SetMapMode,SetPixel,SetPixelV,SetTextAlign,SetTextColor,StretchBlt,TextOutA,TextOutW")

# Stage-2 slice 31 — networking / crypto / common UI / version / setup.
# ws2_32 — the socket functions carry their CANONICAL Windows
# ordinals (name@ordinal) because real PEs (ftp.exe, telnet.exe, …)
# import them BY ORDINAL, not by name. Without the ordinal pin, an
# ordinal-import of "@23" (socket) would bind to whatever our export
# list happened to place 23rd, calling the wrong function with the
# wrong ABI shape and faulting. The fixed ordinals below match
# %SystemRoot%\System32\ws2_32.dll (stable since Win2000). Functions
# without a numeric Windows ordinal keep lld's sequential assignment.
# The pinned ordinals (1-23, 52, 55, 111-116, 151) are exactly the
# ones ftp.exe imports by ordinal; the legacy names ftp imports by
# name (the wide GetAddrInfoW/GetNameInfoW/FreeAddrInfoW/GetHostNameW
# + WSARecv) are added below and resolve by name, so their ordinals
# are left to lld's sequential assignment (no collision with the
# pinned set).
duetos_stub_dll(ws2_32 0x10190000 "accept@1,bind@2,closesocket@3,connect@4,getpeername@5,getsockname@6,getsockopt@7,htonl@8,htons@9,inet_addr@10,inet_ntoa@11,ioctlsocket@12,listen@13,ntohl@14,ntohs@15,recv@16,recvfrom@17,select@18,send@19,sendto@20,setsockopt@21,shutdown@22,socket@23,gethostbyname@55,WSAGetLastError@111,WSASetLastError@112,WSAStartup@115,WSACleanup@116,WSARecv@90,__WSAFDIsSet@151,GetAddrInfoW,GetNameInfoW,FreeAddrInfoW,GetHostNameW,gethostname,getnameinfo,inet_pton,inet_ntop,getaddrinfo,freeaddrinfo,htonll,ntohll,WSAEnumProtocolsA,WSAEnumProtocolsW,WSAIoctl,WSACreateEvent,WSACloseEvent,WSASetEvent,WSAResetEvent,WSAEventSelect,WSAEnumNetworkEvents,WSAWaitForMultipleEvents")
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

# HLSL compiler — userland d3dcompiler.dll. Real lex + parse + emit
# of a tiny HLSL subset; produces a deterministic DXBC-shaped blob.
# See userland/libs/d3dcompiler/d3dcompiler.c.
duetos_stub_dll(d3dcompiler 0x102E0000 "D3DCompile,D3DCompile2,D3DCreateBlob,D3DReflect,D3DDisassemble,DuetOS_D3DCompiler_PeekBlobMagic")

# vulkan-1.dll - Win32 PE library that any Vulkan-using game / app
# imports as `vulkan-1.dll`. The directory + .c basename use the
# underscore form (`vulkan_1`) because bash dollar-substitution in
# build-stub-dll.sh chokes on dashes; the 4th arg to the macro
# overrides the OUTPUT BASENAME so the embedded PE file is named
# `vulkan-1.dll` exactly. v0 surface: lifecycle (Create/Destroy
# instance/device, GetDeviceQueue, *WaitIdle), enumeration, version
# query, GetInstanceProcAddr / GetDeviceProcAddr string lookup,
# DuetOS_Vk_GetStatsCounter diagnostic accessor.
duetos_stub_dll(vulkan_1 0x102F0000 "vkCreateInstance,vkDestroyInstance,vkEnumeratePhysicalDevices,vkCreateDevice,vkDestroyDevice,vkGetDeviceQueue,vkDeviceWaitIdle,vkQueueWaitIdle,vkEnumerateInstanceVersion,vkGetInstanceProcAddr,vkGetDeviceProcAddr,DuetOS_Vk_GetStatsCounter,DuetOS_Vk_ClearFramebufferRgba,DuetOS_Vk_CreateSurface,DuetOS_Vk_DestroySurface,DuetOS_Vk_Present,vkCreateShaderModule,vkDestroyShaderModule,vkAllocateMemory,vkFreeMemory,vkCreateBuffer,vkDestroyBuffer,vkBindBufferMemory,vkMapMemory,vkUnmapMemory,vkCreateImage,vkDestroyImage,vkBindImageMemory,vkCreateCommandPool,vkDestroyCommandPool,vkAllocateCommandBuffers,vkBeginCommandBuffer,vkEndCommandBuffer,vkCmdClearColorImage,vkQueueSubmit,vkCreatePipelineLayout,vkDestroyPipelineLayout,vkCreateRenderPass,vkDestroyRenderPass,vkCreateGraphicsPipelines,vkCreateComputePipelines,vkDestroyPipeline,vkCmdBindPipeline,vkCmdDraw,vkCmdDispatch,vkCmdBindVertexBuffers,vkCmdBindIndexBuffer,vkUpdateDescriptorSets,vkCreateDescriptorSetLayout,vkDestroyDescriptorSetLayout,vkCreateDescriptorPool,vkDestroyDescriptorPool,vkAllocateDescriptorSets,vkCmdBindDescriptorSets" "vulkan-1")


# ----------------------------------------------------------------------------
# KARL — Kernel Address Randomized Link (OpenBSD-style).
#
# When ON, the per-TU object order passed to the linker is randomized using
# tools/build/karl-shuffle.py. The shuffle is seeded so a given build is
# reproducible (DUETOS_KARL_SEED env var pins it; otherwise we draw a value
# at configure time), but two cleanly-configured builds with different seeds
# produce kernels whose function VAs do NOT match. KARL complements KASLR:
# KASLR randomizes the BASE on every boot, KARL randomizes the OFFSETS
# inside the binary on every build. A single function-pointer leak no
# longer derandomizes the rest of the image.
#
# Constraints the shuffle respects:
#   - .text.boot / .rodata.boot / .bss.boot all come from one TU (boot.S)
#     and are filtered into their own sections by the linker script, so a
#     shuffle of the input list cannot move them across .text.
#   - The linker script's ENTRY(_start) resolves the entry point by symbol
#     after link, so the boot.S object's link-position is irrelevant.
#   - C++ static-constructor ordering is governed by `.init_array.NNN`
#     priority slots in the linker script (KEEP'd in priority order); the
#     KERNEL_INITCALL macro registers each callback into an explicit phase
#     enum + RunPhase() dispatcher — no source-order coupling there either.
#   - The symbols TU pin (`symbols_stub.cpp` / `symbols_generated.cpp`) and
#     the kernel-blob TU stay at the tail of the source list because the
#     `add_executable` calls below append them AFTER the shuffled list.
#     That preserves the two-stage symbol-table contract documented at
#     the top of this file.
# ----------------------------------------------------------------------------
option(DUETOS_KARL "Enable KARL: randomize kernel-object link order per build" OFF)

if(DUETOS_KARL)
    set(_karl_seed "$ENV{DUETOS_KARL_SEED}")
    if(_karl_seed STREQUAL "")
        # No explicit seed — draw one at configure time. string(RANDOM) is
        # deterministic only within a single configure run, so a `--fresh`
        # reconfigure picks a new value (intentional: we want the kernel to
        # actually re-randomize across builds).
        string(RANDOM LENGTH 9 ALPHABET "0123456789" _karl_seed)
        # Strip a leading zero if present so the seed parses as a clean
        # base-10 integer in the Python helper.
        string(REGEX REPLACE "^0+" "" _karl_seed "${_karl_seed}")
        if(_karl_seed STREQUAL "")
            set(_karl_seed "1")
        endif()
    endif()
    set(DUETOS_KARL_BUILD_SEED "${_karl_seed}")
    set(DUETOS_KARL_SEED_RECORD "${CMAKE_CURRENT_BINARY_DIR}/karl-seed.txt")
    set(DUETOS_KARL_SHUFFLE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build/karl-shuffle.py")

    # Pipe the source list into karl-shuffle.py via a temp file, collect
    # the shuffled list back, and replace DUETOS_KERNEL_SHARED_SOURCES
    # with it. Configure-time work so the generator (Ninja) sees a stable
    # order on every incremental build until configure runs again.
    string(REPLACE ";" "\n" _karl_stdin "${DUETOS_KERNEL_SHARED_SOURCES}")
    set(_karl_tmp "${CMAKE_CURRENT_BINARY_DIR}/karl-input.txt")
    file(WRITE "${_karl_tmp}" "${_karl_stdin}\n")
    execute_process(
        COMMAND python3 "${DUETOS_KARL_SHUFFLE_SCRIPT}"
                --seed "${DUETOS_KARL_BUILD_SEED}"
                --record "${DUETOS_KARL_SEED_RECORD}"
        INPUT_FILE "${_karl_tmp}"
        OUTPUT_VARIABLE _karl_stdout
        RESULT_VARIABLE _karl_rc
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT _karl_rc EQUAL 0)
        message(FATAL_ERROR
            "KARL shuffle failed (rc=${_karl_rc}). seed=${DUETOS_KARL_BUILD_SEED}\n"
            "Output: ${_karl_stdout}")
    endif()
    string(REPLACE "\n" ";" DUETOS_KERNEL_SHARED_SOURCES "${_karl_stdout}")
    # Remove any empty trailing element from the split.
    list(REMOVE_ITEM DUETOS_KERNEL_SHARED_SOURCES "")
    list(LENGTH DUETOS_KERNEL_SHARED_SOURCES _karl_count)
    message(STATUS "KARL enabled — link order randomized (seed=${DUETOS_KARL_BUILD_SEED}, ${_karl_count} sources). Record: ${DUETOS_KARL_SEED_RECORD}")
else()
    set(DUETOS_KARL_BUILD_SEED "0")
endif()

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
# ----------------------------------------------------------------------------
# Rust leaf targets.
#
# Subsystem crates are Rust rlibs; `kernel/rust` is the single staticlib
# link unit that depends on them. This avoids duplicate core/alloc runtime
# objects when more than one Rust subsystem is linked into the C++ kernel.
#
# Adding a new Rust crate: add it to the root Cargo workspace, add it as a
# dependency of `kernel/rust/Cargo.toml`, add its hand-written C header to
# the include list below, then expose C++ wrappers through the owning
# subsystem directory.
# ----------------------------------------------------------------------------
add_subdirectory(rust)

set(USBCLASS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/usb/class_rust/include")
set(USBHID_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/usb/hid_rust/include")
set(DUETFS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/fs/duetfs/include")
set(NETPARSERS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/net/parsers_rust/include")
set(MSCSCSI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/usb/msc_scsi_rust/include")
set(IMGMETA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/util/img_meta_rust/include")
set(EXECMETA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/loader/exec_meta_rust/include")
# Skeleton crates — no current C++ caller, but the include dirs
# stay on the search path so the FFI headers are reachable the
# instant a caller appears.
set(NTFS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/fs/ntfs_rust/include")
set(EXFAT_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/fs/exfat_rust/include")
set(EXT4_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/fs/ext4_rust/include")
set(ACPIRUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/acpi/acpi_rust/include")
set(SMBIOSRUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/smbios_rust/include")
set(PCICAPS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/pci/caps_rust/include")
set(MULTIBOOT2RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mm/multiboot2_rust/include")
set(WIFI80211_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/net/wifi80211_rust/include")
set(HCIRUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/net/hci_rust/include")
set(TLSRUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/net/tls_rust/include")
set(VTRUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/util/vt_parser_rust/include")
set(NVIDIA_GSP_FW_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/gpu/nvidia_gsp_fw_rust/include")
set(AMD_GFX_FW_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/gpu/amd_gfx_fw_rust/include")
set(BCM43XX_FW_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/net/bcm43xx_fw_rust/include")
set(RTL88XX_FW_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/net/rtl88xx_fw_rust/include")
set(IWLWIFI_FW_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/net/iwlwifi_fw_rust/include")
set(DMAR_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/iommu/dmar_rust/include")
set(IVRS_RUST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/drivers/iommu/ivrs_rust/include")

# Stage 1 needs a stub `kernel_elf_blob` so ramfs.cpp's references
# to kBinKernelElfBytes / kBinKernelElfBytes_len link cleanly.
# Stage 2 swaps in the real (or zero-len) blob populated by
# DUETOS_INSTALLER_KERNEL_EMBED. (DUETOS_KERNEL_BLOB_GEN is also
# referenced below for the stage-2 emit; set both here.)
set(DUETOS_KERNEL_BLOB_GEN "${CMAKE_SOURCE_DIR}/tools/build/gen-kernel-blob.sh")
set(DUETOS_KERNEL_BLOB_STAGE1_S "${CMAKE_CURRENT_BINARY_DIR}/kernel_elf_blob_stage1_stub.S")
add_custom_command(
    OUTPUT "${DUETOS_KERNEL_BLOB_STAGE1_S}"
    COMMAND "${DUETOS_KERNEL_BLOB_GEN}"
            "${DUETOS_KERNEL_BLOB_STAGE1_S}"
            "--empty"
    DEPENDS "${DUETOS_KERNEL_BLOB_GEN}"
    COMMENT "Generating stage-1 kernel-blob stub (always empty — stage 2 swaps in the real one)"
    VERBATIM)

add_executable(duetos-kernel-stage1
    ${DUETOS_KERNEL_SHARED_SOURCES}
    util/symbols_stub.cpp
    "${DUETOS_KERNEL_BLOB_STAGE1_S}"
)
target_link_libraries(duetos-kernel-stage1 PRIVATE "${DUETOS_KERNEL_RUST_STATIC_LIB}")
target_include_directories(duetos-kernel-stage1 PRIVATE
    "${USBCLASS_INCLUDE_DIR}"
    "${USBHID_INCLUDE_DIR}"
    "${DUETFS_INCLUDE_DIR}"
    "${NETPARSERS_INCLUDE_DIR}"
    "${MSCSCSI_INCLUDE_DIR}"
    "${IMGMETA_INCLUDE_DIR}"
    "${EXECMETA_INCLUDE_DIR}"
    "${NTFS_INCLUDE_DIR}"
    "${EXFAT_INCLUDE_DIR}"
    "${EXT4_INCLUDE_DIR}"
    "${ACPIRUST_INCLUDE_DIR}"
    "${SMBIOSRUST_INCLUDE_DIR}"
    "${PCICAPS_INCLUDE_DIR}"
    "${MULTIBOOT2RUST_INCLUDE_DIR}"
    "${WIFI80211_INCLUDE_DIR}"
    "${HCIRUST_INCLUDE_DIR}"
    "${TLSRUST_INCLUDE_DIR}"
    "${VTRUST_INCLUDE_DIR}"
    "${NVIDIA_GSP_FW_RUST_INCLUDE_DIR}"
    "${AMD_GFX_FW_RUST_INCLUDE_DIR}"
    "${BCM43XX_FW_RUST_INCLUDE_DIR}"
    "${RTL88XX_FW_RUST_INCLUDE_DIR}"
    "${IWLWIFI_FW_RUST_INCLUDE_DIR}"
    "${DMAR_RUST_INCLUDE_DIR}"
    "${IVRS_RUST_INCLUDE_DIR}"
)
add_dependencies(duetos-kernel-stage1 ${DUETOS_KERNEL_RUST_TARGET})
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
# Optional: embed the stage-1 kernel ELF bytes into stage 2 so the disk
# installer can write a real /system/boot/duetos-kernel.elf onto the
# freshly-formatted system partition. Off by default — embedding ~10 MiB
# roughly doubles the kernel image size (and therefore the ISO + the
# memory GRUB loads at boot time). Operators who want a fully self-
# installable image enable this; iteration loops keep the cost off.
#
# Implementation note: `.incbin` is processed by the assembler in
# constant time, no matter how big the file. A constexpr u8 array
# literal would balloon compile time linearly with file size.
# ----------------------------------------------------------------------------
option(DUETOS_INSTALLER_KERNEL_EMBED
    "Embed stage-1 kernel.elf bytes for the disk installer (doubles kernel size)" OFF)

set(DUETOS_KERNEL_BLOB_S "${CMAKE_CURRENT_BINARY_DIR}/kernel_elf_blob.S")
if(DUETOS_INSTALLER_KERNEL_EMBED)
    add_custom_command(
        OUTPUT "${DUETOS_KERNEL_BLOB_S}"
        COMMAND "${DUETOS_KERNEL_BLOB_GEN}"
                "${DUETOS_KERNEL_BLOB_S}"
                "$<TARGET_FILE:duetos-kernel-stage1>"
        DEPENDS duetos-kernel-stage1 "${DUETOS_KERNEL_BLOB_GEN}"
        COMMENT "Generating .incbin blob for stage-1 kernel ELF (installer kernel-embed enabled)"
        VERBATIM)
else()
    # Off path: emit a trivial blob with len = 0 so the symbols
    # exist for the linker but the installer detects "no embedded
    # kernel.elf" and prints the staging-required note.
    add_custom_command(
        OUTPUT "${DUETOS_KERNEL_BLOB_S}"
        COMMAND "${DUETOS_KERNEL_BLOB_GEN}"
                "${DUETOS_KERNEL_BLOB_S}"
                "--empty"
        DEPENDS "${DUETOS_KERNEL_BLOB_GEN}"
        COMMENT "Generating empty installer kernel-embed stub (DUETOS_INSTALLER_KERNEL_EMBED=OFF)"
        VERBATIM)
endif()

# ----------------------------------------------------------------------------
# Stage 2: final kernel. Same source set as stage 1, but the stub is
# replaced by the generated TU. The generated TU defines the same
# three extern "C" symbols the resolver looks up, now populated with
# real data.
# ----------------------------------------------------------------------------
add_executable(duetos-kernel
    ${DUETOS_KERNEL_SHARED_SOURCES}
    "${DUETOS_SYMBOLS_GENERATED}"
    "${DUETOS_KERNEL_BLOB_S}"
)
target_link_libraries(duetos-kernel PRIVATE "${DUETOS_KERNEL_RUST_STATIC_LIB}")
target_include_directories(duetos-kernel PRIVATE
    "${USBCLASS_INCLUDE_DIR}"
    "${USBHID_INCLUDE_DIR}"
    "${DUETFS_INCLUDE_DIR}"
    "${NETPARSERS_INCLUDE_DIR}"
    "${MSCSCSI_INCLUDE_DIR}"
    "${IMGMETA_INCLUDE_DIR}"
    "${EXECMETA_INCLUDE_DIR}"
    "${NTFS_INCLUDE_DIR}"
    "${EXFAT_INCLUDE_DIR}"
    "${EXT4_INCLUDE_DIR}"
    "${ACPIRUST_INCLUDE_DIR}"
    "${SMBIOSRUST_INCLUDE_DIR}"
    "${PCICAPS_INCLUDE_DIR}"
    "${MULTIBOOT2RUST_INCLUDE_DIR}"
    "${WIFI80211_INCLUDE_DIR}"
    "${HCIRUST_INCLUDE_DIR}"
    "${TLSRUST_INCLUDE_DIR}"
    "${VTRUST_INCLUDE_DIR}"
    "${NVIDIA_GSP_FW_RUST_INCLUDE_DIR}"
    "${AMD_GFX_FW_RUST_INCLUDE_DIR}"
    "${BCM43XX_FW_RUST_INCLUDE_DIR}"
    "${RTL88XX_FW_RUST_INCLUDE_DIR}"
    "${IWLWIFI_FW_RUST_INCLUDE_DIR}"
    "${DMAR_RUST_INCLUDE_DIR}"
    "${IVRS_RUST_INCLUDE_DIR}"
)
add_dependencies(duetos-kernel ${DUETOS_KERNEL_RUST_TARGET})

# Deliberate-panic build flag, consumed by kernel_main and triggered
# by tools/debug/test-panic.sh. OFF for normal builds — the demo panic
# halts the kernel on purpose and must not ship in a release preset.
option(DUETOS_PANIC_DEMO "Insert a deliberate Panic() at end of kernel_main (test-panic.sh)" OFF)
if(DUETOS_PANIC_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_PANIC_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_PANIC_DEMO=1)
endif()

# Turn on Intel VT-d translation at boot (RTADDR + GCMD.TE +
# context-cache + IOTLB invalidate) for every DMA Remapping
# Hardware Unit reported by the ACPI DMAR table. With identity-
# passthrough page tables (slice 27c) the IOMMU translates every
# IOVA back to itself, so existing DMA continues to work — the
# kernel just gains the ability to refuse a future DMA from
# unknown source-id (slice 28+ wires that part).
#
# ON by default: the VT-d path builds a full identity map (IOVA == phys
# for 0..512 GiB), so every existing driver's physical-address DMA keeps
# working unchanged while a buggy/malicious device is confined to the
# mapped range — the DMA-protection the hardware-safety contract calls
# for. Safe to default on because (a) the enable no-ops cleanly when no
# DMAR table is present (QEMU without `-device intel-iommu`, machines
# without VT-d), (b) a failed enable logs + leaves translation off rather
# than wedging, and (c) `iommu=off` on the kernel cmdline is the boot-time
# escape hatch if a real-hardware regression is suspected.
# tools/test/iommu-smoke.sh / DUETOS_IOMMU_DEVICE=1 tools/qemu/run.sh
# exercise it under QEMU's `-device intel-iommu`.
option(DUETOS_IOMMU_ENABLE "Enable Intel VT-d translation at boot (RTADDR + GCMD.TE)" ON)
if(DUETOS_IOMMU_ENABLE)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_IOMMU_ENABLE=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_IOMMU_ENABLE=1)
endif()

# Strict-mode companion to DUETOS_IOMMU_ENABLE: when ON, a failed
# IOMMU enable at boot PANICS the kernel instead of silently
# leaving translation off.
#
# Without this flag, an enable failure today logs a warning and
# continues — useful for development (you don't lose the boot just
# because intel-iommu wasn't plugged into the QEMU command). For
# production, the gentler behaviour is a foot-gun: a deployment
# that THINKS it has IOMMU defense but actually doesn't is
# worse than one that knows it has none. Set this flag in any
# release build that depends on the IOMMU for its threat model.
#
# Matrix:
#   ENABLE=OFF, REQUIRE=*    : translation off, no enable attempted (dev)
#   ENABLE=ON,  REQUIRE=OFF  : try to enable, log + continue on failure
#   ENABLE=ON,  REQUIRE=ON   : try to enable, PANIC on failure (release)
option(DUETOS_IOMMU_REQUIRE "Panic at boot if IOMMU enable was requested but failed" OFF)
if(DUETOS_IOMMU_REQUIRE)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_IOMMU_REQUIRE=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_IOMMU_REQUIRE=1)
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

# KARL — bake the build seed into both stage targets so the boot-info
# banner can print which seed produced this image. The seed flows into
# `build_config.h` as `kKarlBuildSeed`; the banner prints it at boot.
# The shuffle decision itself was made at configure time (above);
# these defines are pure metadata for triage.
if(DUETOS_KARL)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_KARL=1 DUETOS_KARL_BUILD_SEED=${DUETOS_KARL_BUILD_SEED})
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_KARL=1 DUETOS_KARL_BUILD_SEED=${DUETOS_KARL_BUILD_SEED})
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

# Stack-protector — wiki/security/Linux-CVE-Audit.md class CC.
# `-fstack-protector-strong` emits the canary prologue/epilogue on
# any function with a local array, an `alloca`, or an address-taken
# local. The TU-level `-fno-stack-protector` override on
# security/stack_canary.cpp (above) keeps the canary updater itself
# from sampling __stack_chk_guard mid-write. Setting this flag here
# means the compiler default doesn't matter — what the kernel gets
# is explicit.
target_compile_options(duetos-kernel        PRIVATE -fstack-protector-strong)
target_compile_options(duetos-kernel-stage1 PRIVATE -fstack-protector-strong)

if(DUETOS_LTO)
    set(DUETOS_LTO_FLAGS -flto=thin)
    target_compile_options(duetos-kernel        PRIVATE ${DUETOS_LTO_FLAGS})
    target_compile_options(duetos-kernel-stage1 PRIVATE ${DUETOS_LTO_FLAGS})
    target_link_options(duetos-kernel        PRIVATE ${DUETOS_LTO_FLAGS})
    target_link_options(duetos-kernel-stage1 PRIVATE ${DUETOS_LTO_FLAGS})
    message(STATUS "DUETOS_LTO=ON — building kernel with -flto=thin")
endif()

# Compiler-instrumented sanitizer suite (plan D5 + D5-followup).
#
# Only the diagnostic sanitizers whose `__ubsan_handle_*` call sites
# resolve to the in-tree runtime in `kernel/diag/ubsan.cpp` are
# usable here. ASan / TSan / MSan need shadow memory and a large
# host-style runtime the freestanding x86_64-unknown-elf kernel
# cannot host (clang also rejects `-fsanitize=kernel-address` for
# this target — see the top-level `DUETOS_KASAN` option); the
# in-tree KASAN-equivalent diagnostics (`DUETOS_KASAN`) are the
# ASan stand-in and are wired through the debug preset, not here.
#
# When ON, every kernel TU is built with the sanitizer flag set
# below. Each emitted handler logs one structured klog warning +
# serial line and returns ("visibility, not enforcement"). Use the
# `x86_64-debug-ubsan` preset for the default set, or the heavier
# `x86_64-debug-san` preset (adds the integer family) for
# adversarial runs.
option(DUETOS_ENABLE_UBSAN "Build the kernel with the diagnostic sanitizer suite (UBSan + nullability + float-divide-by-zero)" OFF)
# Opt-in for the integer family (`unsigned-integer-overflow`,
# `implicit-conversion`, …). OFF by default and NOT in the default
# debug preset: the kernel deliberately relies on unsigned
# wraparound (hashing, ring indices, PRNGs), so this set is mostly
# false positives in steady state and would drown the real UB
# signal. The `x86_64-debug-san` preset turns it on for runs that
# specifically hunt conversion/truncation bugs.
option(DUETOS_ENABLE_UBSAN_INTEGER "Also enable the noisy -fsanitize=integer family (opt-in; x86_64-debug-san)" OFF)
if(DUETOS_ENABLE_UBSAN)
    # `-fno-sanitize=function` suppresses the call-through-mismatched-
    # function-pointer-type check (`__ubsan_handle_function_type_mismatch`).
    # That check uses RTTI metadata the kernel deliberately does not
    # build; with it on, every callback dispatch (sched task entry,
    # IRQ handler, syscall thunk) emits a handler symbol the runtime
    # has no use for and the link fails. The remaining classes
    # (signed overflow, OOB, divrem, alignment, nullability,
    # float-divide-by-zero, …) cover what we want without dragging
    # in the C++-RTTI-shaped CFI surface. Every recoverable
    # `__ubsan_handle_*` these can emit has a handler in
    # `kernel/diag/ubsan.cpp`, so the link stays closed regardless
    # of which checks fire.
    set(DUETOS_UBSAN_FLAGS
        -fsanitize=undefined,nullability,float-divide-by-zero
        -fno-sanitize=function
        -fno-sanitize-trap=all)
    if(DUETOS_ENABLE_UBSAN_INTEGER)
        list(APPEND DUETOS_UBSAN_FLAGS -fsanitize=integer)
    endif()
    target_compile_options(duetos-kernel        PRIVATE ${DUETOS_UBSAN_FLAGS})
    target_compile_options(duetos-kernel-stage1 PRIVATE ${DUETOS_UBSAN_FLAGS})
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_UBSAN=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_UBSAN=1)
endif()

# Debug builds upgrade the toolchain's -fstack-protector-strong to
# -fstack-protector-all: a stack cookie on EVERY function, not just
# the ones the strong heuristic flags (arrays / address-of-local /
# alloca). clang takes the last -fstack-protector-* on the command
# line, so appending here wins for the kernel targets without
# touching the shared toolchain (release keeps -strong: an
# every-function prologue/epilogue is real per-call overhead the
# steady-state kernel shouldn't pay). The guard symbol and the
# __stack_chk_fail → panic path are unchanged.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(duetos-kernel        PRIVATE -fstack-protector-all)
    target_compile_options(duetos-kernel-stage1 PRIVATE -fstack-protector-all)
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
# KARL symbol-map artefact for triage.
#
# A KARL build produces a unique address map per-seed; a panic RIP can only
# be decoded against the map that built it. Emit `kernel.symbols` next to
# the linked ELF (sorted by address) on every build — cheap, useful with or
# without KARL. Include in the ISO so a recovery shell can read it.
#
# We don't fail the build if `nm` is missing — the kernel is still linked
# and bootable; only the symbols artefact is skipped, with a status note.
# ----------------------------------------------------------------------------
find_program(NM_BIN nm)
if(NM_BIN)
    add_custom_command(TARGET duetos-kernel POST_BUILD
        COMMAND sh -c "${NM_BIN} -n \"$<TARGET_FILE:duetos-kernel>\" > \"$<TARGET_FILE_DIR:duetos-kernel>/kernel.symbols\""
        COMMENT "Generating KARL kernel.symbols map (nm -n) for triage"
        VERBATIM)
else()
    message(STATUS "kernel.symbols artefact skipped (nm not found on PATH).")
endif()

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
        # Best-effort copy of the KARL symbol-map artefact for triage.
        # If nm was missing at configure time (no NM_BIN) the file
        # wasn't generated; `cmake -E copy` over a missing source is
        # a hard error, so we test+copy via sh and swallow failure.
        # The ISO build itself is not gated on its presence.
        COMMAND sh -c "test -f \"$<TARGET_FILE_DIR:duetos-kernel>/kernel.symbols\" && cp \"$<TARGET_FILE_DIR:duetos-kernel>/kernel.symbols\" \"${DUETOS_ISO_STAGE}/boot/kernel.symbols\" || true"

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

# ----------------------------------------------------------------------------
# AArch64 assemble-verify target.
#
# The second-tier-pillar starter set (kernel/arch/aarch64/*.S) does
# not yet build into a runnable kernel — the C++ side that
# AArch64UserSyncException / KernelMainAArch64 / AArch64SyscallDispatch
# resolves to hasn't been written. But the .S files must stay
# valid AArch64 asm so a future kernel slice picks up clean
# code rather than rotted syntax. This rule assembles each
# file with clang's built-in aarch64 backend (no system cross-
# toolchain needed) and just checks the .o appears non-empty.
# Drives off `make duetos-aarch64-asm-verify` or as a dependency
# of `all`.
# ----------------------------------------------------------------------------
file(GLOB DUETOS_AARCH64_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/arch/aarch64/*.S")

if(DUETOS_AARCH64_SOURCES)
    set(_aarch64_objs)
    foreach(_aa_src IN LISTS DUETOS_AARCH64_SOURCES)
        get_filename_component(_aa_name "${_aa_src}" NAME_WE)
        set(_aa_obj "${CMAKE_CURRENT_BINARY_DIR}/aarch64-verify/${_aa_name}.o")
        add_custom_command(
            OUTPUT  "${_aa_obj}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/aarch64-verify"
            COMMAND ${CMAKE_C_COMPILER} --target=aarch64-elf
                                        -ffreestanding -nostdinc
                                        -c "${_aa_src}" -o "${_aa_obj}"
            DEPENDS "${_aa_src}"
            COMMENT "AArch64 assemble-verify: ${_aa_name}.S"
            VERBATIM)
        list(APPEND _aarch64_objs "${_aa_obj}")
    endforeach()
    add_custom_target(duetos-aarch64-asm-verify ALL
        DEPENDS ${_aarch64_objs})
else()
    message(STATUS "duetos-aarch64-asm-verify target disabled (no kernel/arch/aarch64/*.S).")
endif()
