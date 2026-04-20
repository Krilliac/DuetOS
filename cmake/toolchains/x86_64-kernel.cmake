# CustomOS freestanding x86_64 kernel toolchain.
#
# Compiles kernel TUs with clang targeting a bare-metal ELF64 image.
# No hosted libc. No exceptions. No RTTI. No SSE/MMX/x87 in kernel code —
# the FPU/SSE save area is per-thread and managed by the scheduler, not
# implicitly used for codegen.
#
# Usage: `cmake --preset x86_64-debug` (see CMakePresets.json).

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Compilers — hard-pinned to clang because our inline asm and attributes
# assume clang semantics, and because we want identical codegen across
# developer machines and CI.
set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)

# Skip the compiler-works sanity probe — it tries to link a hosted
# executable, which fails for a freestanding toolchain.
set(CMAKE_C_COMPILER_WORKS   1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# We drive the link ourselves with ld.lld and a hand-written linker script.
set(CMAKE_LINKER lld)

# Target triple: plain ELF, no OS.
set(CUSTOMOS_KERNEL_TARGET "x86_64-unknown-none-elf")

set(CUSTOMOS_KERNEL_C_FLAGS
    "--target=${CUSTOMOS_KERNEL_TARGET}"
    -ffreestanding
    # Stack canaries: compiler emits a per-function prologue that plants
    # a cookie from __stack_chk_guard and an epilogue that verifies it
    # before return. On mismatch, compiler-inserted code calls
    # __stack_chk_fail, which we panic from. Use -fstack-protector-strong
    # so any function with an array, address-of-local, or alloca gets
    # protected (unlike vanilla -fstack-protector which only gates on
    # char arrays > 8 bytes).
    #
    # -mstack-protector-guard=global picks __stack_chk_guard via the
    # ordinary ELF symbol path instead of the glibc TLS form (%fs:0x28),
    # which doesn't apply in freestanding mode because we don't set up
    # the TLS slot.
    -fstack-protector-strong
    -mstack-protector-guard=global
    -fno-pic
    -fno-pie
    -fno-builtin
    -fno-common
    -fno-omit-frame-pointer
    -mno-red-zone
    -mno-mmx
    -mno-sse
    -mno-sse2
    -mno-80387
    -mgeneral-regs-only
    -mcmodel=kernel
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
)

set(CUSTOMOS_KERNEL_CXX_FLAGS
    ${CUSTOMOS_KERNEL_C_FLAGS}
    -fno-exceptions
    -fno-rtti
    -fno-threadsafe-statics
    -fno-use-cxa-atexit
    -std=c++23
)

set(CUSTOMOS_KERNEL_ASM_FLAGS
    "--target=${CUSTOMOS_KERNEL_TARGET}"
)

set(CUSTOMOS_KERNEL_LINK_FLAGS
    "--target=${CUSTOMOS_KERNEL_TARGET}"
    -fuse-ld=lld
    -nostdlib
    -static
    -Wl,--build-id=none
    -Wl,-z,max-page-size=0x1000
    -Wl,-z,noexecstack
)

# Expose as cached strings so per-target CMakeLists.txt files can consume them
# without re-deriving.
string(REPLACE ";" " " _kernel_c_flags   "${CUSTOMOS_KERNEL_C_FLAGS}")
string(REPLACE ";" " " _kernel_cxx_flags "${CUSTOMOS_KERNEL_CXX_FLAGS}")
string(REPLACE ";" " " _kernel_asm_flags "${CUSTOMOS_KERNEL_ASM_FLAGS}")
string(REPLACE ";" " " _kernel_ld_flags  "${CUSTOMOS_KERNEL_LINK_FLAGS}")

set(CMAKE_C_FLAGS_INIT           "${_kernel_c_flags}"    CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_INIT         "${_kernel_cxx_flags}"  CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS_INIT         "${_kernel_asm_flags}"  CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_INIT  "${_kernel_ld_flags}"   CACHE STRING "" FORCE)

# Freestanding targets never search the host sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
