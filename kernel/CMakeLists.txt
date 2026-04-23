# CustomOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.
#
# The embedded symbol table (used by the panic dump path to resolve RIPs to
# function/file/line) needs a two-stage build:
#
#   1. Link `customos-kernel-stage1.elf` with a stub symbol table. Every
#      function / data symbol in this image already sits at its final VA
#      because the generated TU is pinned to the end of the kernel source
#      list — rodata growth in stage 2 happens strictly AFTER every other
#      symbol.
#
#   2. Run `tools/gen-symbols.sh` against stage 1 to produce
#      `symbols_generated.cpp`, a sorted `{addr, size, line, name, file}`
#      table, and relink the final `customos-kernel.elf` with it in place
#      of the stub.
#
# The final image is what the ISO target packages. Stage 1 is a throwaway.

set(CUSTOMOS_KERNEL_SHARED_SOURCES
    core/heartbeat.cpp
    core/hexdump.cpp
    core/klog.cpp
    core/main.cpp
    core/panic.cpp
    core/process.cpp
    core/reboot.cpp
    core/recovery.cpp
    core/elf_loader.cpp
    core/pe_loader.cpp
    core/random.cpp
    core/result.cpp
    core/ring3_smoke.cpp
    core/runtime_checker.cpp
    subsystems/graphics/graphics.cpp
    subsystems/linux/ring3_smoke.cpp
    subsystems/linux/syscall.cpp
    subsystems/linux/syscall_entry.S
    subsystems/translation/translate.cpp
    subsystems/win32/event_syscall.cpp
    subsystems/win32/file_syscall.cpp
    subsystems/win32/heap.cpp
    subsystems/win32/heap_syscall.cpp
    subsystems/win32/mutex_syscall.cpp
    subsystems/win32/stubs.cpp
    subsystems/win32/tls_syscall.cpp
    subsystems/win32/vmap_syscall.cpp
    core/shell.cpp
    core/stack_canary.cpp
    core/symbols.cpp
    core/fault_domain.cpp
    core/syscall.cpp
    core/time_syscall.cpp
    debug/bp_syscall.cpp
    debug/extable.cpp
    acpi/acpi.cpp
    apps/calculator.cpp
    apps/clock.cpp
    apps/files.cpp
    apps/notes.cpp
    arch/x86_64/ap_trampoline.S
    arch/x86_64/boot.S
    acpi/aml.cpp
    arch/x86_64/cpu_info.cpp
    arch/x86_64/hypervisor.cpp
    arch/x86_64/exceptions.S
    arch/x86_64/gdt.cpp
    arch/x86_64/hpet.cpp
    arch/x86_64/idt.cpp
    arch/x86_64/ioapic.cpp
    arch/x86_64/lapic.cpp
    arch/x86_64/pic.cpp
    arch/x86_64/retpoline_thunks.S
    arch/x86_64/rtc.cpp
    arch/x86_64/serial.cpp
    arch/x86_64/smbios.cpp
    arch/x86_64/smp.cpp
    arch/x86_64/thermal.cpp
    arch/x86_64/timer.cpp
    arch/x86_64/traps.cpp
    arch/x86_64/usermode.S
    cpu/percpu.cpp
    debug/breakpoints.cpp
    debug/probes.cpp
    drivers/input/ps2kbd.cpp
    drivers/input/ps2mouse.cpp
    drivers/audio/audio.cpp
    drivers/gpu/gpu.cpp
    drivers/net/net.cpp
    drivers/pci/pci.cpp
    drivers/power/power.cpp
    drivers/storage/ahci.cpp
    drivers/storage/block.cpp
    drivers/storage/nvme.cpp
    drivers/usb/hid_descriptor.cpp
    drivers/usb/msc_scsi.cpp
    drivers/usb/usb.cpp
    drivers/usb/xhci.cpp
    drivers/video/calendar.cpp
    drivers/video/console.cpp
    drivers/video/cursor.cpp
    drivers/video/font8x8.cpp
    drivers/video/framebuffer.cpp
    drivers/video/menu.cpp
    drivers/video/taskbar.cpp
    drivers/video/widget.cpp
    fs/exfat.cpp
    fs/ext4.cpp
    fs/fat32.cpp
    fs/gpt.cpp
    fs/ntfs.cpp
    fs/ramfs.cpp
    fs/tmpfs.cpp
    fs/vfs.cpp
    mm/address_space.cpp
    mm/frame_allocator.cpp
    mm/kheap.cpp
    mm/page.cpp
    mm/paging.cpp
    mm/user_copy.S
    net/stack.cpp
    sched/context_switch.S
    sched/sched.cpp
    security/attack_sim.cpp
    security/guard.cpp
    sync/spinlock.cpp
)

# core/stack_canary.cpp provides __stack_chk_fail and the
# RandomizeStackCanary helper. The latter updates the cookie at
# runtime; if ANY function in this file gets compiled with stack
# protection, the prologue/epilogue would sample __stack_chk_guard
# before/after the update and mismatch. The source uses
# __attribute__((no_stack_protector)) on the two functions that
# care; -fno-stack-protector on the whole TU is belt + braces.
set_source_files_properties(
    core/stack_canary.cpp
    PROPERTIES COMPILE_OPTIONS "-fno-stack-protector"
)

# ----------------------------------------------------------------------------
# Host-side userland build: userland/apps/hello_pe/hello.c is compiled
# with clang targeting x86_64-pc-windows-msvc and linked by lld-link
# into a real freestanding PE/COFF .exe. The bytes are embedded into a
# C++ constexpr u8 header that ramfs.cpp includes, so /bin/hello.exe
# appears on the boot filesystem without a disk backend.
#
# This relies on host clang + lld-link + python3 being present, which
# the dev container ships with. A future slice will guard this with a
# CMake probe and fall back to a hand-laid byte array if the
# toolchain is missing.
# ----------------------------------------------------------------------------
set(CUSTOMOS_HELLO_PE_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_pe/hello.c")
set(CUSTOMOS_HELLO_PE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_pe.h")
set(CUSTOMOS_HELLO_PE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-pe.sh")
set(CUSTOMOS_EMBED_BLOB_SCRIPT "${CMAKE_SOURCE_DIR}/tools/embed-blob.py")

add_custom_command(
    OUTPUT "${CUSTOMOS_HELLO_PE_HEADER}"
    COMMAND "${CUSTOMOS_HELLO_PE_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_HELLO_PE_HEADER}"
    DEPENDS
        "${CUSTOMOS_HELLO_PE_SRC}"
        "${CUSTOMOS_HELLO_PE_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello.exe (freestanding PE)"
    VERBATIM
)

# ramfs.cpp includes the generated header. Add it to the shared
# source list so BOTH stages see the dependency and the custom
# command fires on first configure.
list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_HELLO_PE_HEADER}")

# ----------------------------------------------------------------------------
# Embed a real Windows PE (windows-kill.exe, a small standalone
# Win32 console utility — 79 KiB, 12 DLL deps, 100 imported
# functions, TLS callbacks). This is NOT a file we can run: v0
# has no Win32 subsystem, no ntdll, nothing to resolve the
# imports against. But the kernel PE loader's diagnostic path
# (PeReport) exercises every directory on this image, giving a
# concrete gap report on boot.
#
# This is the tractable substitute for "download Chrome and try
# to run it": real Windows PE, real imports, but small enough
# that embedding it into a constexpr u8 array doesn't balloon
# the kernel.
# ----------------------------------------------------------------------------
set(CUSTOMOS_WINKILL_SRC "${CMAKE_SOURCE_DIR}/userland/apps/windows_kill/windows-kill.exe")
set(CUSTOMOS_WINKILL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_winkill_pe.h")

add_custom_command(
    OUTPUT "${CUSTOMOS_WINKILL_HEADER}"
    COMMAND python3
            "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
            "${CUSTOMOS_WINKILL_SRC}"
            "${CUSTOMOS_WINKILL_HEADER}"
            kBinWinKillBytes
            --namespace "customos::fs::generated"
    DEPENDS
        "${CUSTOMOS_WINKILL_SRC}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding real Windows PE /bin/windows-kill.exe"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_WINKILL_HEADER}")

# ----------------------------------------------------------------------------
# Third PE fixture: hello_winapi.exe — first userland program
# that talks to the CustomOS Win32 subsystem through a real
# Import Directory. Built via llvm-dlltool (kernel32.lib) +
# clang + lld-link. See tools/build-hello-winapi.sh and
# .claude/knowledge/pe-subsystem-v0.md for the layered
# mechanism.
# ----------------------------------------------------------------------------
set(CUSTOMOS_HELLO_WINAPI_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/hello.c")
# Every .def file in the hello_winapi dir becomes a separate
# import library feeding lld-link. Glob-dependency means adding
# a new .def (e.g. for a future DLL stub set) automatically
# triggers a rebuild without touching this CMakeLists.
file(GLOB CUSTOMOS_HELLO_WINAPI_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/*.def")
set(CUSTOMOS_HELLO_WINAPI_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_winapi.h")
set(CUSTOMOS_HELLO_WINAPI_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-winapi.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_HELLO_WINAPI_HEADER}"
    COMMAND "${CUSTOMOS_HELLO_WINAPI_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_HELLO_WINAPI_HEADER}"
    DEPENDS
        "${CUSTOMOS_HELLO_WINAPI_SRC}"
        ${CUSTOMOS_HELLO_WINAPI_DEFS}
        "${CUSTOMOS_HELLO_WINAPI_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello_winapi.exe (Win32 import path)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_HELLO_WINAPI_HEADER}")

set(CUSTOMOS_KERNEL_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/linker.ld")

# Shared link flags — applied identically to both stages so the symbol
# addresses extracted from stage 1 are valid for stage 2.
function(customos_apply_kernel_link_flags target)
    target_link_options(${target} PRIVATE
        -T${CUSTOMOS_KERNEL_LINKER_SCRIPT}
        -Wl,--gc-sections
        -Wl,--no-undefined
        -Wl,-n
    )
    set_target_properties(${target} PROPERTIES
        LINK_DEPENDS "${CUSTOMOS_KERNEL_LINKER_SCRIPT}"
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
add_executable(customos-kernel-stage1
    ${CUSTOMOS_KERNEL_SHARED_SOURCES}
    core/symbols_stub.cpp
)
set_target_properties(customos-kernel-stage1 PROPERTIES
    OUTPUT_NAME "customos-kernel-stage1.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    # Stage 1 is internal plumbing — don't install or package it.
    EXCLUDE_FROM_ALL FALSE
)
target_include_directories(customos-kernel-stage1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
customos_apply_kernel_link_flags(customos-kernel-stage1)

# ----------------------------------------------------------------------------
# Generate symbols_generated.cpp from the stage-1 ELF.
#
# gen-symbols.sh reads every higher-half function symbol, resolves
# addr -> (file, line) via addr2line, and emits a sorted-by-address
# `{addr, size, line, name, file}` table. The resulting TU is what the
# stage-2 kernel links against.
# ----------------------------------------------------------------------------
set(CUSTOMOS_SYMBOLS_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/symbols_generated.cpp")

add_custom_command(
    OUTPUT "${CUSTOMOS_SYMBOLS_GENERATED}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
            "$<TARGET_FILE:customos-kernel-stage1>"
            "${CUSTOMOS_SYMBOLS_GENERATED}"
            "${CMAKE_SOURCE_DIR}"
    DEPENDS customos-kernel-stage1 "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
    COMMENT "Extracting kernel symbol table from stage-1 ELF"
    VERBATIM
)

# ----------------------------------------------------------------------------
# Stage 2: final kernel. Same source set as stage 1, but the stub is
# replaced by the generated TU. The generated TU defines the same
# three extern "C" symbols the resolver looks up, now populated with
# real data.
# ----------------------------------------------------------------------------
add_executable(customos-kernel
    ${CUSTOMOS_KERNEL_SHARED_SOURCES}
    "${CUSTOMOS_SYMBOLS_GENERATED}"
)

# Deliberate-panic build flag, consumed by kernel_main and triggered
# by tools/test-panic.sh. OFF for normal builds — the demo panic
# halts the kernel on purpose and must not ship in a release preset.
option(CUSTOMOS_PANIC_DEMO "Insert a deliberate Panic() at end of kernel_main (test-panic.sh)" OFF)
if(CUSTOMOS_PANIC_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_PANIC_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_PANIC_DEMO=1)
endif()

# Deliberate stack-smash build flag. Enables a small in-kernel_main
# block that overruns a local array past its stack canary, forcing
# __stack_chk_fail to fire on return. Intended for verifying the
# canary infrastructure works end-to-end; OFF for normal builds.
option(CUSTOMOS_CANARY_DEMO "Insert a deliberate stack smash at end of kernel_main (verifies stack-canary panic path)" OFF)
if(CUSTOMOS_CANARY_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_CANARY_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_CANARY_DEMO=1)
endif()

# Red-team attack-simulation flag. Runs the AttackSim suite once
# at the end of kernel_main, exercising every runtime-checker
# detector by performing the attack a rootkit would and
# verifying the detector catches it. OFF for normal boot — the
# simulations escalate the security guard to Enforce mode and
# the block write-guard to Deny, which would poison every
# subsequent image load / sensitive-LBA write for the session.
option(CUSTOMOS_ATTACK_SIM "Run the AttackSim red-team suite at end of kernel_main" OFF)
if(CUSTOMOS_ATTACK_SIM)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_ATTACK_SIM=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_ATTACK_SIM=1)
endif()


# Deliberate-CPU-exception build flag, consumed by kernel_main and
# triggered by tools/test-trap.sh. Executes `ud2` to take a #UD fault
# so the trap dispatcher's crash-dump path can be verified end-to-end
# (extractable BEGIN/END record, symbolized RIP, backtrace). OFF for
# normal builds.
option(CUSTOMOS_TRAP_DEMO "Execute ud2 at end of kernel_main to take #UD (test-trap.sh)" OFF)
if(CUSTOMOS_TRAP_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_TRAP_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_TRAP_DEMO=1)
endif()


# Initial boot mode: desktop (windowed shell) vs TTY (fullscreen
# framebuffer console). Runtime toggle with Ctrl+Alt+T works
# regardless of this flag; it only affects what the user sees
# when the kernel first hits kernel_main's compose phase. Useful
# for an install / rescue build that prefers text-first UX.
option(CUSTOMOS_BOOT_TTY "Boot straight into TTY mode instead of the windowed desktop" OFF)
if(CUSTOMOS_BOOT_TTY)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_BOOT_TTY=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_BOOT_TTY=1)
endif()

set_target_properties(customos-kernel PROPERTIES
    OUTPUT_NAME "customos-kernel.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(customos-kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

customos_apply_kernel_link_flags(customos-kernel)

# ----------------------------------------------------------------------------
# Bootable ISO — uses GRUB as a third-party loader until our own UEFI boot
# loader exists. If grub-mkrescue / xorriso aren't installed, the kernel
# still builds; only the `customos-iso` target is skipped, with a status
# message explaining what to install.
# ----------------------------------------------------------------------------

find_program(GRUB_MKRESCUE grub-mkrescue)
find_program(XORRISO       xorriso)

if(GRUB_MKRESCUE AND XORRISO)
    set(CUSTOMOS_ISO_STAGE  "${CMAKE_CURRENT_BINARY_DIR}/iso-stage")
    set(CUSTOMOS_ISO_OUTPUT "${CMAKE_BINARY_DIR}/customos.iso")
    set(CUSTOMOS_GRUB_CFG   "${CMAKE_SOURCE_DIR}/boot/grub/grub.cfg")

    add_custom_command(
        OUTPUT "${CUSTOMOS_ISO_OUTPUT}"

        # Lay out the ISO root exactly the way grub.cfg expects.
        COMMAND ${CMAKE_COMMAND} -E rm -rf  "${CUSTOMOS_ISO_STAGE}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CUSTOMOS_ISO_STAGE}/boot/grub"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:customos-kernel>"
                                         "${CUSTOMOS_ISO_STAGE}/boot/customos-kernel.elf"
        COMMAND ${CMAKE_COMMAND} -E copy "${CUSTOMOS_GRUB_CFG}"
                                         "${CUSTOMOS_ISO_STAGE}/boot/grub/grub.cfg"

        # Produce the ISO. grub-mkrescue embeds the i386-pc boot image so the
        # result is bootable on both legacy BIOS (via QEMU's default SeaBIOS)
        # and — when GRUB's EFI modules are present on the host — UEFI.
        COMMAND ${GRUB_MKRESCUE} --compress=xz -o "${CUSTOMOS_ISO_OUTPUT}"
                                 "${CUSTOMOS_ISO_STAGE}"

        DEPENDS customos-kernel "${CUSTOMOS_GRUB_CFG}"
        COMMENT "Building bootable customos.iso"
        VERBATIM
    )

    add_custom_target(customos-iso ALL
        DEPENDS "${CUSTOMOS_ISO_OUTPUT}"
    )
else()
    message(STATUS "customos-iso target disabled (grub-mkrescue or xorriso not found).")
    message(STATUS "  Install with: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools")
endif()
