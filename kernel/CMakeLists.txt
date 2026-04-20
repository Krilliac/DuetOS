# CustomOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.

set(CUSTOMOS_KERNEL_SOURCES
    core/heartbeat.cpp
    core/klog.cpp
    core/main.cpp
    core/panic.cpp
    core/recovery.cpp
    acpi/acpi.cpp
    arch/x86_64/ap_trampoline.S
    arch/x86_64/boot.S
    arch/x86_64/exceptions.S
    arch/x86_64/gdt.cpp
    arch/x86_64/idt.cpp
    arch/x86_64/ioapic.cpp
    arch/x86_64/lapic.cpp
    arch/x86_64/pic.cpp
    arch/x86_64/serial.cpp
    arch/x86_64/smp.cpp
    arch/x86_64/timer.cpp
    arch/x86_64/traps.cpp
    cpu/percpu.cpp
    drivers/input/ps2kbd.cpp
    drivers/pci/pci.cpp
    mm/frame_allocator.cpp
    mm/kheap.cpp
    mm/page.cpp
    mm/paging.cpp
    sched/context_switch.S
    sched/sched.cpp
    sync/spinlock.cpp
)

add_executable(customos-kernel ${CUSTOMOS_KERNEL_SOURCES})

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

# Drive the link with our hand-written linker script. `LINK_DEPENDS` makes
# ninja/make re-link when the script changes (CMake doesn't infer this from
# `-T` alone).
set(CUSTOMOS_KERNEL_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/linker.ld")

target_link_options(customos-kernel PRIVATE
    -T${CUSTOMOS_KERNEL_LINKER_SCRIPT}
    -Wl,--gc-sections
    -Wl,--no-undefined
    -Wl,-n
)

set_target_properties(customos-kernel PROPERTIES
    LINK_DEPENDS "${CUSTOMOS_KERNEL_LINKER_SCRIPT}"
)

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
