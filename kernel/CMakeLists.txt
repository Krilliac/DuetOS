# CustomOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.

set(CUSTOMOS_KERNEL_SOURCES
    core/main.cpp
    arch/x86_64/boot.S
    arch/x86_64/serial.cpp
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
