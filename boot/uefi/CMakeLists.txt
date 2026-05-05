# DuetOS — UEFI BOOTX64.EFI build, Phase A.
#
# The kernel toolchain pins `--target=x86_64-unknown-none-elf` and a
# freestanding ELF link. UEFI needs the opposite: `--target=
# x86_64-unknown-windows` so clang emits the Microsoft x64 calling
# convention, plus a PE32+ link with subsystem=EFI Application. Two
# different toolchains in the same CMake tree don't mix into a normal
# `add_executable`, so this directory drives clang/lld-link directly
# via add_custom_command.
#
# Output: ${CMAKE_BINARY_DIR}/boot/uefi/BOOTX64.EFI
#
# v0 acceptance: file builds clean, has the right Subsystem=10 byte
# in the PE32+ optional header, and runs to the "DuetOS UEFI loader
# v0 (Phase A)" banner under qemu-system-x86_64 -bios OVMF. Phase B
# will replace efi_main with a real ELF loader + multiboot2-shim
# handoff to the existing kernel/arch/x86_64/boot.S entry.

set(DUETOS_UEFI_OUTPUT_DIR "${CMAKE_BINARY_DIR}/boot/uefi")
set(DUETOS_UEFI_OBJ "${DUETOS_UEFI_OUTPUT_DIR}/main.obj")
set(DUETOS_UEFI_EFI "${DUETOS_UEFI_OUTPUT_DIR}/BOOTX64.EFI")
set(DUETOS_UEFI_SRC "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")
set(DUETOS_UEFI_HDR "${CMAKE_CURRENT_SOURCE_DIR}/efi_types.h")

# Compile flags. Mirror the kernel's freestanding/no-RTTI/no-exceptions
# stance, but DROP every kernel-specific flag (stack canaries reference
# __stack_chk_guard which doesn't exist in UEFI; -mno-sse breaks Microsoft
# x64 which assumes SSE2 is available; -fcf-protection wants endbr64 prologues
# our 200-line loader has no use for). The result is a deliberately
# minimal flag set — every flag has a comment.
set(DUETOS_UEFI_CXX_FLAGS
    --target=x86_64-unknown-windows  # Microsoft x64 ABI + PE/COFF output
    -ffreestanding                   # No hosted runtime; we own everything
    -fno-exceptions                  # No EH unwinder available
    -fno-rtti                        # No typeinfo
    -fno-stack-protector             # No __stack_chk_guard in UEFI
    -fno-stack-check                 # No __chkstk in UEFI
    -mno-red-zone                    # Interrupts can fire; red zone unsafe
    -nostdinc                        # No system headers
    -nostdlib                        # No libc
    -fshort-wchar                    # CHAR16 = unsigned short, not int32
    -std=c++23                       # Match the rest of the project
    -Wall -Wextra -Wpedantic         # Same warning floor as the kernel
    -Werror                          # Zero-warning policy
    -O2
)

# Compile main.cpp -> main.obj. Phase A is small enough to compile
# in one step; Phase B can split into per-protocol TUs if it grows.
add_custom_command(
    OUTPUT  "${DUETOS_UEFI_OBJ}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${DUETOS_UEFI_OUTPUT_DIR}"
    COMMAND "${CMAKE_C_COMPILER}" ${DUETOS_UEFI_CXX_FLAGS}
            -c "${DUETOS_UEFI_SRC}"
            -o "${DUETOS_UEFI_OBJ}"
    DEPENDS "${DUETOS_UEFI_SRC}" "${DUETOS_UEFI_HDR}"
    COMMENT "Compiling UEFI loader main.cpp (PE/COFF, MS x64)"
    VERBATIM
)

# Link main.obj -> BOOTX64.EFI. lld-link is the Windows-flavor linker
# from the LLVM project; it produces PE32+ output natively. The flags
# pinned here:
#
#   /subsystem:efi_application  -> Subsystem byte = 10 in the optional
#                                  header. Tells the firmware "this is
#                                  a loader, not a kernel module".
#   /entry:efi_main             -> Override the default _DllMainCRTStartup
#                                  / mainCRTStartup entry. Our entry is
#                                  in the global namespace, no decoration.
#   /nodefaultlib               -> No CRT / kernel32 / msvcrt linkage.
#   /dll                        -> EFI binaries are technically DLLs
#                                  (Subsystem=10 is recognised on a DLL
#                                  image; non-DLL EFI binaries aren't a
#                                  thing the firmware accepts).
#   /machine:x64                -> Explicit; lld can usually infer.
find_program(DUETOS_LLD_LINK lld-link REQUIRED)
add_custom_command(
    OUTPUT  "${DUETOS_UEFI_EFI}"
    COMMAND "${DUETOS_LLD_LINK}"
            /subsystem:efi_application
            /entry:efi_main
            /nodefaultlib
            /dll
            /noimplib   # Suppress the BOOTX64.lib import file lld-link
                        # generates as a side-effect of /dll; nothing in
                        # the build links against it.
            /machine:x64
            "/out:${DUETOS_UEFI_EFI}"
            "${DUETOS_UEFI_OBJ}"
    DEPENDS "${DUETOS_UEFI_OBJ}"
    COMMENT "Linking BOOTX64.EFI (PE32+ EFI Application)"
    VERBATIM
)

# Top-level target so `cmake --build … --target duetos-uefi` works
# and so the kernel build's final stage can depend on it once Phase
# B wires the loader into the bootable-image producer.
add_custom_target(duetos-uefi ALL DEPENDS "${DUETOS_UEFI_EFI}")

# Surface the path to downstream targets (e.g. tools/build that
# stages a FAT32 ESP image).
set(DUETOS_UEFI_EFI "${DUETOS_UEFI_EFI}" CACHE INTERNAL "Path to built BOOTX64.EFI")

message(STATUS "DuetOS UEFI loader: ${DUETOS_UEFI_EFI}")
