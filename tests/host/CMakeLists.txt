# tests/host/CMakeLists.txt
#
# Hosted unit tests for arch-agnostic kernel TUs. Builds with the
# host system compiler (clang/g++ from PATH), links against host
# glibc + libstdc++, and runs as ordinary Linux processes under
# CTest. Compared with the qemu-smoke matrix, these tests:
#
#   - run in milliseconds, not seconds
#   - can be parallelised across cores
#   - work under sanitizers (ASan, UBSan, TSan)
#   - assert directly on return values rather than grepping log
#     lines
#
# Scope today: trivially-pure kernel TUs whose behavior is fully
# determined by their inputs (no MMIO, no MSRs, no kernel state).
# As the kernel matures and more TUs grow `#ifdef DUETOS_HOST_TEST`
# shims around hardware accessors, the coverage here grows. See
# .claude/knowledge/host-tests-v0.md for the planned expansion.
#
# Standalone project — NOT included from the root CMakeLists.txt.
# Build via:
#
#   cmake --preset host-tests
#   cmake --build build/host-tests
#   ctest --test-dir build/host-tests --output-on-failure

cmake_minimum_required(VERSION 3.25)
project(duetos-host-tests CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Common warnings + treat-as-errors. Mirrors the kernel build's
# discipline so a host test that compiles cleanly at home compiles
# cleanly in CI.
add_compile_options(
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wconversion -Wsign-conversion
)

# Sanitizer toggle. CI runs each preset with sanitizers enabled
# (ASan + UBSan together is well-supported by clang). Local devs
# can opt out via -DDUETOS_HOST_TESTS_SANITIZERS=OFF.
option(DUETOS_HOST_TESTS_SANITIZERS "Enable ASan + UBSan for host unit tests" ON)
if(DUETOS_HOST_TESTS_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Make the kernel headers reachable from host-test sources via the
# same include prefix the kernel uses (e.g. `#include "util/types.h"`).
# Only headers that are arch-neutral and dependency-light should
# actually be #included from a host test; pulling in something that
# transitively requires kernel-only globals would fail to link.
include_directories("${CMAKE_SOURCE_DIR}/../../kernel")

enable_testing()

# ---------------------------------------------------------------
# Test helper. Header-only single-file ASSERT framework — far
# lighter than gtest/Catch2, which would be the wrong dep for a
# fledgling host-test path. A failed ASSERT prints file:line +
# message and returns non-zero from main; CTest treats that as a
# test failure.
# ---------------------------------------------------------------

add_library(host_test_helper INTERFACE)
target_include_directories(host_test_helper INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")

# ---------------------------------------------------------------
# Individual test executables. Each test_*.cpp links against
# host_test_helper + (where applicable) the kernel TU under test.
#
# Adding a new test:
#   1. Drop test_<thing>.cpp into this directory.
#   2. Append `add_host_test(<thing>)` below.
#   3. Cite the kernel TU it covers in the .cpp's top-of-file
#      comment so the cross-reference is greppable.
# ---------------------------------------------------------------

function(add_host_test name)
    add_executable(test_${name} test_${name}.cpp)
    target_link_libraries(test_${name} PRIVATE host_test_helper)
    add_test(NAME ${name} COMMAND test_${name})
endfunction()

add_host_test(result)
add_host_test(string)
add_host_test(cvt)
add_host_test(text_hash)
