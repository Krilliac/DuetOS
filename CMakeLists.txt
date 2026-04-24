cmake_minimum_required(VERSION 3.25)

# Toolchain must be set via -DCMAKE_TOOLCHAIN_FILE (or a preset). Detect
# that early so a plain `cmake -B build` fails loudly instead of trying
# to build kernel code with the host toolchain.
if(NOT CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR
        "DuetOS must be configured via a preset.\n"
        "  cmake --preset x86_64-debug    # or x86_64-release\n"
        "Plain `cmake -B build` is not supported — the kernel is freestanding.")
endif()

project(DuetOS
    VERSION   0.0.1
    LANGUAGES C CXX ASM
    DESCRIPTION "DuetOS — from-scratch x86_64 OS with native PE execution")

# Pinned by the active preset. Today x86_64 is the only value; aarch64 lands
# behind its own preset + toolchain file when that tier opens up.
set(DUETOS_ARCH "x86_64" CACHE STRING "Target architecture")
if(NOT DUETOS_ARCH STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported DUETOS_ARCH: ${DUETOS_ARCH}")
endif()

# Turn on folder organization in multi-config generators.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Every target in this tree is freestanding. Reject any accidental attempt
# to link against a hosted runtime.
set(CMAKE_C_EXTENSIONS   OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

# Sub-projects append their output into this, so the top-level build
# driver can produce the disk image.
set(DUETOS_ARTIFACTS "" CACHE INTERNAL "Accumulated build artifacts")

add_subdirectory(kernel)

# ----------------------------------------------------------------------------
# Test harness — boots the built kernel in QEMU and greps the serial log for
# the set of expected boot signatures emitted by the ring3 smoke probes.
#
# The test runs only if the QEMU launcher script is present (it is installed
# on-demand; see CLAUDE.md's "live-test runtime tooling" section). When the
# tools are missing `ctest` just skips with an informative message instead
# of failing.
#
# SparkEngine inspires the shape here: a single comprehensive smoke test
# that exercises the full boot path, rather than per-subsystem unit tests
# that would require a hosted test runtime the kernel can't provide.
# ----------------------------------------------------------------------------
enable_testing()

set(DUETOS_QEMU_RUN "${CMAKE_SOURCE_DIR}/tools/qemu/run.sh")
set(DUETOS_SMOKE_DRIVER "${CMAKE_SOURCE_DIR}/tools/ctest-boot-smoke.sh")

add_test(NAME duetos-boot-smoke
    COMMAND "${DUETOS_SMOKE_DRIVER}" "${CMAKE_BINARY_DIR}"
)
set_tests_properties(duetos-boot-smoke PROPERTIES
    LABELS "smoke;boot;win32"
    TIMEOUT 60
)

message(STATUS "")
message(STATUS "DuetOS configured.")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Toolchain  : ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  C compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Linker     : ${CMAKE_LINKER}")
message(STATUS "")
