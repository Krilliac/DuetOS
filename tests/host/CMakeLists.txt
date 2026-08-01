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
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(
    NAME cxxeh_context_contract
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/test/cxxeh-context-contract.py"
)

add_test(
    NAME verify_pe_exports
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/build/test_verify_pe_exports.py"
)

add_test(
    NAME gen_fix_patches_retirement
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/build/test_gen_fix_patches.py"
)

add_test(
    NAME capability_access_static
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/capability-access-static.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

# A tracked TU that includes an untracked header compiles for the
# session that wrote both and for nobody else. Targeted-path staging
# (CLAUDE_PARALLEL.md forbids `git add -A`) is exactly how a new
# header gets left behind, so gate it here rather than in CI-only.
add_test(
    NAME include_tracked
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/include-tracked-audit.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME iphlpapi_socket_abi
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/iphlpapi-socket-abi.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME win32_syscall_numbers
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-syscall-numbers.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME dll_def_exports
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-dll-def-exports.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

# The VMM's own vmm-tests target only builds on a WHP-capable
# Windows host; this models the same GDB packet length rules in
# Python so the untrusted-socket contract is checked everywhere.
add_test(
    NAME vmm_gdb_packet_vectors
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/vmm-gdb-packet-vectors.py"
)

add_test(
    NAME kernel32_32_exports_complete
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-dll-def-exports.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
            --lib kernel32_32
            --warn-unexported
            --strict
)

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
add_host_test(message_abi)
target_sources(test_message_abi PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp")
# Phase A dynamic fix-discovery: decision logic is a freestanding header
# (syscall/inferred_gap_decide.h), so the test needs no kernel TU.
add_host_test(inferred_gap)
# HPET tick->ns scaling is a freestanding header (time/hpet_scale.h),
# so this needs no kernel TU. Pins the u64-overflow-at-5.12h fix.
add_host_test(hpet_scale)
add_host_test(thunk_retirement_policy)
add_host_test(pe_unwind_bounds)
# Demand-grown ring-3 stacks: the reservation planner and the #PF
# classifier are both freestanding (proc/user_stack.h), so the decision
# that gates committing memory for an untrusted PE is pinned here
# rather than only observed in a boot log.
add_host_test(user_stack)
# Phase B dynamic fix-discovery: config-proposal decision is freestanding
# (env/config_proposal_decide.h), no kernel TU.
add_host_test(config_proposal)
add_host_test(string)
add_host_test(cvt)
add_host_test(text_hash)
add_host_test(d3dcompiler)
# GDI region geometry: freestanding header (userland/libs/gdi32/gdi32_region.h),
# included by relative path — no extra target_sources needed.
add_host_test(gdi32_region)
# Off-screen GDI surface arithmetic: freestanding header
# (kernel/subsystems/win32/gdi_surface_math.h). Pins the guest-controlled
# allocation math (32-bit pixel-count wrap, DIB DWORD row padding,
# INT32_MIN biHeight) and the two-surface blit clip.
add_host_test(gdi_surface)
# i386 kernel32 companion path / seek-resolution core: freestanding
# header (userland/libs/kernel32_32/kernel32_32_paths.h), no kernel TU.
add_host_test(kernel32_32_paths)
# i386 kernel32 companion QueryPerformanceCounter epoch extension:
# freestanding header (kernel32_32_qpc.h). The 32-bit syscall return
# path truncates SYS_NOW_NS, so the wrap fixup is load-bearing.
add_host_test(kernel32_32_time)
# i386 kernel32 companion code-page / collation core: freestanding
# header (kernel32_32_nls.h), no kernel TU.
add_host_test(kernel32_32_nls)
# SMBIOS Type 17 (Memory Device) field decode: freestanding header
# (kernel/arch/x86_64/smbios_decode.h), no kernel TU. Covers the Size
# encoding's KB-vs-MB unit bit and Extended-Size escape, which a boot on
# any single machine only exercises one branch of.
add_host_test(smbios_type17)
# Telemetry percentage math: freestanding header
# (kernel/diag/telemetry_math.h), no kernel TU. Pins the summed-delta
# aggregate against the mean-of-percentages formula they get confused
# with, plus the torn-read clamps.
add_host_test(telemetry_cpu)
# CPU sensor decode: freestanding header
# (kernel/arch/x86_64/cpu_sensor_math.h), no kernel TU. The reads
# themselves are unverifiable off the target (QEMU models neither the
# AMD SMN aperture nor the Zen P-state MSRs), so the decode half is
# pinned here against synthetic register values instead.
add_host_test(cpu_sensor_math)
# Security-exception identity + boot-token parsing: freestanding header
# (kernel/security/exception_id.h), no kernel TU. This decides WHICH
# image an operator vouched for, so the lenient-direction failures
# (short digest accepted, key prefix mis-matched) are the ones worth
# pinning here rather than by booting.
add_host_test(exception_id)
# Firewall exception spec grammar: freestanding header
# (kernel/net/fw_exception.h), no kernel TU. Fail-closed parser — the
# rejection cases are the load-bearing half.
add_host_test(fw_exception)
add_host_test(damage_rect)
# Banded damage / forced-invalidation fold: freestanding constexpr state
# on DamageBandSet in kernel/drivers/video/framebuffer.h — no kernel TU.
add_host_test(damage_bands)
# Intel 2D BLT surface/rectangle gate and packet encoding are pure; the
# actual MMIO submitter remains gated to real Intel silicon.
add_host_test(intel_blt)
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
add_host_test(app_palette)
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

# PE `.rsrc` resource-directory walker (userland/libs/common/pe_resources.h):
# the three-level tree, string-table bundling, and the malformed-input
# cases that must fail closed. Same header-only warning-gate reasoning as
# kernel32_nls above — the synthetic-image builder is dense index math.
add_host_test(pe_resources)
target_compile_options(test_pe_resources PRIVATE -Wno-conversion -Wno-sign-conversion)

# Icon / cursor decoder (duet_res_pick_icon, duet_res_decode_icon).
# Synthetic PE with hand-crafted RT_GROUP_ICON + RT_ICON resources.
add_host_test(pe_icon_decode)
target_compile_options(test_pe_icon_decode PRIVATE -Wno-conversion -Wno-sign-conversion)

# Delay-load import descriptor walk (kernel/loader/pe_delay_import.h):
# the directory-head bound, per-descriptor truncation, the all-zero
# terminator, and every form the binder must refuse rather than trust.
add_host_test(pe_delay_import)

# Win32 SxS assembly-manifest parser (kernel/loader/manifest.h +
# manifest.cpp): execution level, DPI awareness, long-path awareness,
# SxS dependency extraction, and end-to-end PE resource extraction.
add_host_test(manifest)
target_sources(test_manifest PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/loader/manifest.cpp")
target_compile_options(test_manifest PRIVATE -Wno-conversion -Wno-sign-conversion)

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

# TPM 2.0 wire marshalling (kernel/drivers/tpm/tpm_wire.h): big-endian
# framing, the commandSize back-patch, byte-exact command encodings, and
# hostile-reply rejection. Also pins the sealing-only allow-list: the
# identity-half opcodes (Quote, Certify, ActivateCredential, GetTime, ...)
# must stay refused, so this test fails if anyone adds attestation.
add_host_test(tpm_wire)

# Kernel command-line token parser (kernel/util/cmdline.h): key=value
# lookup incl. prefix collisions, and the strict hex decoder that the TPM
# measured-boot baseline (tpm.baseline=) depends on.
add_host_test(cmdline)

# Font registry (kernel/subsystems/graphics/font.cpp + font8x8.cpp):
# lookup logic, built-in registration, case-insensitive name match,
# height-based fallback, and LookupGlyph dispatch.
add_host_test(font_registry)
target_sources(test_font_registry PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/subsystems/graphics/font.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/font8x8.cpp"
)
