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
    core/klog.cpp
    core/main.cpp
    core/panic.cpp
    core/process.cpp
    core/reboot.cpp
    core/recovery.cpp
    core/ring3_smoke.cpp
    core/stack_canary.cpp
    core/symbols.cpp
    core/syscall.cpp
    acpi/acpi.cpp
    arch/x86_64/ap_trampoline.S
    arch/x86_64/boot.S
    arch/x86_64/exceptions.S
    arch/x86_64/gdt.cpp
    arch/x86_64/hpet.cpp
    arch/x86_64/idt.cpp
    arch/x86_64/ioapic.cpp
    arch/x86_64/lapic.cpp
    arch/x86_64/pic.cpp
    arch/x86_64/serial.cpp
    arch/x86_64/smp.cpp
    arch/x86_64/timer.cpp
    arch/x86_64/traps.cpp
    arch/x86_64/usermode.S
    cpu/percpu.cpp
    drivers/input/ps2kbd.cpp
    drivers/pci/pci.cpp
    drivers/storage/ahci.cpp
    fs/ramfs.cpp
    fs/vfs.cpp
    mm/address_space.cpp
    mm/frame_allocator.cpp
    mm/kheap.cpp
    mm/page.cpp
    mm/paging.cpp
    sched/context_switch.S
    sched/sched.cpp
    sync/spinlock.cpp
)

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
target_include_directories(customos-kernel-stage1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
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

# Tick-budget live-fire build flag. Spawns ring3-cpu-hog which
# infinite-loops in ring 3 with a 50-tick (~500 ms) budget; the
# scheduler's tick-exhausted path kills it. OFF for normal builds;
# opt in to verify the tick-budget kill path.
option(CUSTOMOS_BUDGET_DEMO "Spawn a ring-3 task that spins forever to exercise the tick-budget kill" OFF)
if(CUSTOMOS_BUDGET_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_BUDGET_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_BUDGET_DEMO=1)
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

set_target_properties(customos-kernel PROPERTIES
    OUTPUT_NAME "customos-kernel.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(customos-kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
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
