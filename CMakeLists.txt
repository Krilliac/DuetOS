cmake_minimum_required(VERSION 3.25)

# Toolchain must be set via -DCMAKE_TOOLCHAIN_FILE (or a preset). Detect
# that early so a plain `cmake -B build` fails loudly instead of trying
# to build kernel code with the host toolchain.
if(NOT CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR
        "CustomOS must be configured via a preset.\n"
        "  cmake --preset x86_64-debug    # or x86_64-release\n"
        "Plain `cmake -B build` is not supported — the kernel is freestanding.")
endif()

project(CustomOS
    VERSION   0.0.1
    LANGUAGES C CXX ASM
    DESCRIPTION "CustomOS — from-scratch x86_64 OS with native PE execution")

# Pinned by the active preset. Today x86_64 is the only value; aarch64 lands
# behind its own preset + toolchain file when that tier opens up.
set(CUSTOMOS_ARCH "x86_64" CACHE STRING "Target architecture")
if(NOT CUSTOMOS_ARCH STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported CUSTOMOS_ARCH: ${CUSTOMOS_ARCH}")
endif()

# Turn on folder organization in multi-config generators.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Every target in this tree is freestanding. Reject any accidental attempt
# to link against a hosted runtime.
set(CMAKE_C_EXTENSIONS   OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

# Sub-projects append their output into this, so the top-level build
# driver can produce the disk image.
set(CUSTOMOS_ARTIFACTS "" CACHE INTERNAL "Accumulated build artifacts")

add_subdirectory(kernel)

message(STATUS "")
message(STATUS "CustomOS configured.")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Toolchain  : ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  C compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Linker     : ${CMAKE_LINKER}")
message(STATUS "")
