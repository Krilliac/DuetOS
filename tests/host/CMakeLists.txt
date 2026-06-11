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
# shims around hardware accessors, the coverage here grows.
#
# Standalone project — NOT included from the root CMakeLists.txt.
# Build via (from the repo root):
#
#   cmake -S tests/host -B build/host-tests
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
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic -Werror
        -Wshadow -Wconversion -Wsign-conversion
    )
endif()

# Sanitizer toggle. CI runs each preset with sanitizers enabled
# (ASan + UBSan together is well-supported by clang). Local devs
# can opt out via -DDUETOS_HOST_TESTS_SANITIZERS=OFF.
option(DUETOS_HOST_TESTS_SANITIZERS "Enable ASan + UBSan for host unit tests" ON)
if(DUETOS_HOST_TESTS_SANITIZERS AND NOT MSVC)
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
add_host_test(syscall_error)
target_sources(test_syscall_error PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/syscall/error.cpp")
add_host_test(string)
add_host_test(cvt)
add_host_test(text_hash)
add_host_test(d3dcompiler)
add_host_test(damage_rect)
add_host_test(render_stats)
target_sources(test_render_stats PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/render_stats.cpp"
)

# ECDSA P-256/P-384 verify — compiles the real kernel crypto TUs and
# runs their EcSelfTest natively (replaces the ~200 s under-TCG boot
# copy; that stays gated behind `selftests=full`).
add_host_test(ec)
target_sources(test_ec PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/net/ec.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
)

# X.509 chain verify (HTTPS trust path) — the heaviest boot crypto
# self-test (RSA-4096 + ECDSA + 8 real roots). Hosted native, gating
# every PR; the in-kernel copy stays behind `selftests=full`.
add_host_test(x509_verify)
target_sources(test_x509_verify PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/net/x509_verify.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/net/ec.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/rsa.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/asn1.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/x509.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha384.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/util/datetime.cpp"
)
# x509_verify.cpp documents the OpenSSL fixture-generation commands in
# `//` comments with trailing `\` shell continuations, which trips the
# host build's stricter -Wcomment (the kernel build doesn't enable it).
# These are intentional command documentation, not a code defect, so
# suppress -Wcomment for this target rather than reflow security-critical
# crypto source.
target_compile_options(test_x509_verify PRIVATE -Wno-comment)

# X25519 (Curve25519 ECDH) — the TLS 1.3 key-exchange primitive. RFC 7748
# §5.2 + §6.1 vectors. Pure field arithmetic, no kernel deps.
add_host_test(x25519)
target_sources(test_x25519 PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/crypto/x25519.cpp")
target_compile_options(test_x25519 PRIVATE -Wno-conversion -Wno-sign-conversion)

# RSASSA-PSS / SHA-256 verify — the TLS 1.3 RSA CertificateVerify scheme.
# OpenSSL-generated vector (positive + tamper negatives).
add_host_test(rsa_pss)
target_sources(test_rsa_pss PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/rsa.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
target_compile_options(test_rsa_pss PRIVATE -Wno-conversion -Wno-sign-conversion)

add_host_test(wild_address)
add_host_test(disk_path)
add_host_test(nospec)
add_host_test(saturating)
add_host_test(vfs_resolve)
add_host_test(registry_path)
add_host_test(forwarder)
add_host_test(thunk_hash)
add_host_test(blend)
add_host_test(shadow_atlas)
add_host_test(motion_math)
add_host_test(chrome_text_measure)
add_host_test(app_widgets_bounds)
add_host_test(app_widgets_paint)
add_host_test(app_widgets_events)
add_host_test(widget_group)

# kernel32.dll NLS number-format core (GetNumberFormat / GetCurrencyFormat).
# The header under test is header-only; its authoritative warning gate is
# the freestanding DLL build (-Wall -Wextra -Wpedantic -Werror, no
# -Wconversion), so relax the host harness's extra -Wconversion/
# -Wsign-conversion here — they only fire on legitimate char-index math.
add_host_test(kernel32_nls)
target_compile_options(test_kernel32_nls PRIVATE -Wno-conversion -Wno-sign-conversion)

# Browser omnibox URL-vs-search classifier (kernel/apps/browser/omnibox_classify.h).
add_host_test(omnibox_classify)

# KMalloc small-allocation slab-routing decision logic (kernel/mm/kmalloc_route.h):
# size-class boundaries, route-header encode/decode, KFree discrimination verdicts.
add_host_test(kmalloc_route)

# Autonomic-policy safety shield (kernel/env/policy_shield.h): ShieldConfig
# defaults, the one-call master toggle, ShieldApply rule-floor passthrough,
# and the autonomic=/shields= cmdline parse (incl. prefix-collision guard).
add_host_test(policy_shield)

# Fixed-point neural autonomic policy (kernel/env/neural_policy.cpp): the
# integer forward pass (matmul + >>12 requantize + ReLU), feature
# extraction, and imitation-by-construction (net == rule level-predicates).
add_host_test(neural_policy)
target_sources(test_neural_policy PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/env/neural_policy.cpp")
