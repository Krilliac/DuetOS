#pragma once

#include "util/types.h"

/*
 * DuetOS — central build-flavor configuration.
 *
 * One header, every TU includes it (transitively or directly), every
 * conditional compile-time decision made downstream reads from the
 * `inline constexpr` knobs declared here. The macros that drive these
 * knobs are emitted by the top-level CMakeLists.txt — see the "Build
 * flavor" block there for the per-option default matrix.
 *
 * Why centralise:
 *   - One grep for "kBuildFlavor" finds every site that branches on
 *     debug vs release. Today the codebase has ~75 SelfTest call
 *     sites, a hard-wired klog default threshold, and several hand-
 *     rolled `#ifdef DUETOS_*` macros. None of them know about each
 *     other; flipping "this build is release" used to require
 *     touching N files. Now it requires picking the preset.
 *   - Constexpr knobs let downstream code use `if constexpr (...)`
 *     so the dead branch is provably eliminated by codegen, even at
 *     -O0. Macros + #ifdef would also work but force every caller to
 *     duplicate the gate; constexpr lets them write straight-line
 *     code that the optimizer folds.
 *
 * Style: every knob is declared with a constexpr value derived from
 * the corresponding CMake option's `add_compile_definitions(...)`
 * output. If the macro is undefined we fall back to a documented
 * safe default (always the *less* instrumentation) so that a TU that
 * accidentally compiles without seeing this header behaves like a
 * release build, not like an unintialized one.
 *
 * Context: kernel-only. Userland DLLs do NOT include this header —
 * they're freestanding (see CLAUDE.md "Subsystem isolation"). If a
 * userland DLL needs a build-flavor signal, the kernel exposes it
 * through a dedicated syscall, not through a shared header.
 */

namespace duetos::core
{

// Numeric flavor — must match the values emitted by CMake.
//   1 = Debug, 2 = Release. RelWithDebInfo / MinSizeRel route to
// Release for instrumentation defaults.
enum class BuildFlavor : u8
{
    Debug = 1,
    Release = 2,
};

#ifdef DUETOS_BUILD_FLAVOR
inline constexpr BuildFlavor kBuildFlavor = static_cast<BuildFlavor>(DUETOS_BUILD_FLAVOR);
#else
// Header included from a TU CMake didn't pass DUETOS_BUILD_FLAVOR for
// (e.g. a one-off host-side test). Default to Release so the missing
// define can never silently flip a release binary into debug-only
// instrumentation.
inline constexpr BuildFlavor kBuildFlavor = BuildFlavor::Release;
#endif

inline constexpr bool kIsDebugBuild = (kBuildFlavor == BuildFlavor::Debug);
inline constexpr bool kIsReleaseBuild = (kBuildFlavor == BuildFlavor::Release);

// -----------------------------------------------------------------
// Boot self-tests.
//
// The InitcallRegister(Phase::Earlycon, ...) blocks at the top of
// kernel_main exercise pure utility primitives (Result<T,E>, freestanding
// memset/memcpy/memmove, hexdump formatter, VA-region classifier).
// They have no init side effect — every call panics on failure or
// returns. Skipping them in release halves the early-boot serial
// chatter and saves ~1 ms of boot time on a slow VM.
//
// Real-init-with-validation (RegistryInit then RegistrySelfTest, etc.)
// stays on regardless — those are not pure tests, they double as
// the registry's seed-data wiring.
// -----------------------------------------------------------------
#ifdef DUETOS_BOOT_SELFTESTS
inline constexpr bool kBootSelfTests = (DUETOS_BOOT_SELFTESTS != 0);
#else
inline constexpr bool kBootSelfTests = false;
#endif

// -----------------------------------------------------------------
// Kernel assertions (KASSERT).
//
// `KASSERT(cond, msg)` is a panic-on-false in debug, a no-op in release.
// See kernel/util/kassert.h for the macro itself; this knob is what
// the macro reads to decide whether to emit code at all.
//
// A "release-asserts" preset turns this back on while keeping the
// optimizer at O2 — useful for paranoid production builds where the
// cost of a dead branch on every assert site is worth catching the
// invariant violation early.
// -----------------------------------------------------------------
#ifdef DUETOS_ASSERTS
inline constexpr bool kAssertsEnabled = (DUETOS_ASSERTS != 0);
#else
inline constexpr bool kAssertsEnabled = false;
#endif

// -----------------------------------------------------------------
// Lock-order auditor.
//
// When enabled, every spinlock/mutex acquire records the lock pointer
// + acquire-site in a per-CPU stack. A subsequent acquire that would
// create a back-edge in the lock-order graph triggers a one-shot warn.
// The audit is advisory — never panics — because lock-order violations
// are routinely caught later by deadlock-detection on real hardware.
//
// See kernel/sync/lock_audit.h for the API.
// -----------------------------------------------------------------
#ifdef DUETOS_LOCK_ORDER_AUDIT
inline constexpr bool kLockOrderAudit = (DUETOS_LOCK_ORDER_AUDIT != 0);
#else
inline constexpr bool kLockOrderAudit = false;
#endif

// -----------------------------------------------------------------
// Capability-gate audit verbosity.
//
// Off    — gate runs the cap check, no trace at all.
// Sample — every kCapAuditSampleStride'th call emits a one-line
//          trace; the rest are silent. Default for release.
// Full   — every cap-gated call emits a trace. Verbose; debug-only.
//
// The cap-gate dispatcher reads `kCapAuditMode` and chooses the
// behavior at the syscall boundary. See kernel/security/cap_audit.h.
// -----------------------------------------------------------------
enum class CapAuditMode : u8
{
    Off = 0,
    Sample = 1,
    Full = 2,
};

#ifdef DUETOS_CAP_AUDIT
inline constexpr CapAuditMode kCapAuditMode = static_cast<CapAuditMode>(DUETOS_CAP_AUDIT);
#else
inline constexpr CapAuditMode kCapAuditMode = CapAuditMode::Off;
#endif

/// Sampling stride for `CapAuditMode::Sample`. 1024 means roughly one
/// trace line per ~1ms of busy syscall traffic — visible enough to
/// confirm the gate is firing, quiet enough to not flood serial.
inline constexpr u64 kCapAuditSampleStride = 1024;

// -----------------------------------------------------------------
// Boot-time klog runtime threshold.
//
// The compile-time floor (kKlogMinLevel in klog.h) stays at Trace so
// release binaries can dial Trace back ON via `loglevel t`. This
// knob picks the BOOT-TIME default — debug builds want Debug
// (drivers + IRQ + sched chatter); release builds want Warn
// (warnings + errors + critical only — clean serial capture for
// forensic analysis, demote at runtime via `loglevel`).
//
// Numeric values match LogLevel: Trace=0 Debug=1 Info=2 Warn=3 Error=4 Critical=5.
// -----------------------------------------------------------------
#ifdef DUETOS_KLOG_DEFAULT
inline constexpr u8 kKlogDefaultLevel = static_cast<u8>(DUETOS_KLOG_DEFAULT);
#else
inline constexpr u8 kKlogDefaultLevel = 3; // Warn
#endif

/// Compile-time klog floor. Mirrors the macro
/// `DUETOS_KLOG_COMPILE_FLOOR` defined in klog.h's `#ifndef` block;
/// surfaced here so callers that already include build_config.h can
/// reason about it without dragging in klog.h. KLOG_TRACE / TRACE_V /
/// TRACE_SCOPE call sites compile away when this is above 0.
#ifdef DUETOS_KLOG_COMPILE_FLOOR
inline constexpr u8 kKlogCompileFloor = static_cast<u8>(DUETOS_KLOG_COMPILE_FLOOR);
#else
inline constexpr u8 kKlogCompileFloor = 1; // Debug — matches klog.h fallback
#endif

// -----------------------------------------------------------------
// KASLR — random-base kernel-image relocation at boot.
//
// Today this knob is a placeholder: the real KASLR pass is roadmap
// work (see wiki/reference/Roadmap.md). The flag is in place so a
// future implementation can read from one source of truth without
// touching every TU that wants to know "is my address space
// randomized?". Defaults to ON in both flavors; flip OFF for the
// rare reproducible-RIP debug session.
// -----------------------------------------------------------------
#ifdef DUETOS_KASLR
inline constexpr bool kKaslrEnabled = (DUETOS_KASLR != 0);
#else
inline constexpr bool kKaslrEnabled = false;
#endif

// -----------------------------------------------------------------
// Link-time optimization.
//
// Today this knob does not propagate to compiler/linker flags — the
// CMake option is in place so a future preset can wire `-flto` /
// `-fuse-ld=lld` thinLTO into the toolchain without a TU edit.
// -----------------------------------------------------------------
#ifdef DUETOS_LTO
inline constexpr bool kLtoEnabled = (DUETOS_LTO != 0);
#else
inline constexpr bool kLtoEnabled = false;
#endif

// -----------------------------------------------------------------
// UBSAN runtime.
//
// Mirrors the existing `DUETOS_UBSAN` define from the kernel-side
// CMakeLists.txt. Surfaced here so a `if constexpr (kUbsanRuntime)`
// caller doesn't have to know which header originally introduced
// the macro.
// -----------------------------------------------------------------
#ifdef DUETOS_UBSAN
inline constexpr bool kUbsanRuntime = (DUETOS_UBSAN != 0);
#else
inline constexpr bool kUbsanRuntime = false;
#endif

/// Compile-time short string identifying this build's flavor + most
/// significant knobs. Useful for the boot banner and the crash-dump
/// header so a user who reports a bug can paste it back without
/// digging through the build log.
constexpr const char* BuildFlavorName()
{
    if constexpr (kIsDebugBuild)
    {
        return "debug";
    }
    else
    {
        return "release";
    }
}

} // namespace duetos::core

// -----------------------------------------------------------------
// DUETOS_BOOT_SELFTEST(call)
//
// Wrap a pure-test SelfTest invocation so release builds skip it
// while debug builds run it as before. The `if constexpr` guard
// makes the call dead code that the optimizer drops at any
// optimization level, including -O0.
//
// Use this for selftests with NO init side effect — i.e. the call
// only validates and panics on failure. Don't wrap selftests that
// double as init validation (e.g. RegistrySelfTest after
// RegistryInit, where the test seeds + checks state at the same
// time).
// -----------------------------------------------------------------
#define DUETOS_BOOT_SELFTEST(call)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (::duetos::core::kBootSelfTests)                                                                  \
        {                                                                                                              \
            call;                                                                                                      \
        }                                                                                                              \
    } while (0)
