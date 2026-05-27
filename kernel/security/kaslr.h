#pragma once

#include "util/types.h"

/*
 * DuetOS — KASLR (kernel address-space layout randomization), v0.
 *
 * STATUS
 *   The slide-application machinery is a follow-on slice (depends
 *   on the kernel being built as a PIE with a baked-in relocation
 *   table the early-boot stub can apply). What lands here is the
 *   piece every consumer of "what slide is the kernel running at?"
 *   needs to be able to ask: a single source of truth.
 *
 *   - `KaslrInit` runs once at boot, after `core::RandomInit`,
 *     computes a candidate slide value, and stores it.
 *   - `KaslrGetKernelSlide` returns the slide currently applied
 *     to the kernel image. **Today this returns 0** — the slide is
 *     computed but not yet applied to the image. Consumers (debug
 *     symbol resolver, panic dump, GDB stub) call this so the day
 *     the slide-application stub lands, every consumer sees the
 *     non-zero value without an audit pass.
 *   - `KaslrGetCandidateSlide` returns the value that *would be*
 *     applied if applied. Useful for self-tests and diagnostics.
 *
 *   See wiki/security/Linux-CVE-Audit.md class II for the threat
 *   model. The follow-on slice that applies the slide must build
 *   the kernel with `-fPIE` and emit relocations into a section
 *   the early-boot stub can iterate.
 *
 * CONTEXT
 *   Kernel, called once during boot after `core::RandomInit`. Pure
 *   read after init — `KaslrGetKernelSlide` is `noexcept` and lock-
 *   free.
 */

namespace duetos::security
{

/// Compute a candidate slide value and stash it. No-op if called
/// twice. The slide is page-aligned and bounded so the slid kernel
/// still fits in the canonical high half. Safe to call on a CPU
/// without RDRAND — falls back to the splitmix entropy source via
/// `core::RandomU64()`.
void KaslrInit();

/// The slide currently applied to the kernel image. Today: 0
/// unconditionally — the slide is computed but not applied. The
/// non-zero return comes online when the kernel build flips to
/// PIE + relocations. Consumers that decode kernel addresses
/// (symbol resolver, panic dump) call this so they don't need to
/// be re-audited on the flip day.
u64 KaslrGetKernelSlide();

/// The slide value `KaslrInit` computed, regardless of whether
/// it's been applied. Diagnostics + self-test only.
u64 KaslrGetCandidateSlide();

/// Was KaslrInit called and did it pick a non-zero candidate?
/// (A zero candidate is legitimate — it means "we'd apply zero
/// slide" — not an error.) False before init runs.
bool KaslrInitialized();

/// Per-boot 64-bit pointer-obfuscation mask. Derived from the
/// same RandomU64() source as the candidate slide; non-zero on
/// any boot where KaslrInit ran. Stable across the lifetime of
/// one boot (deterministic during a single session) but
/// unpredictable across cold boots.
///
/// Used by `KaslrMaskPointer` / `KaslrUnmaskPointer` to scrub
/// kernel addresses before exposing them across a trust
/// boundary (panic banner shown over a multiplexed serial line,
/// any future /proc-like surface, syscall return values that
/// might encode a kernel pointer).
u64 KaslrPointerMask();

/// Obfuscate a kernel pointer for cross-boundary printing.
/// Returns `p ^ KaslrPointerMask()`. The result is NOT a valid
/// pointer — the caller must NEVER dereference it. The mask is
/// per-boot, so the same pointer obfuscates to the same masked
/// value within one boot, and an attacker who collects two
/// masked pointers can derive their XOR (relative offsets are
/// preserved). The defense is "leak of one obfuscated kernel
/// pointer does not disclose the kernel base address" — same
/// posture as Linux's `%pK` formatting under
/// `kptr_restrict=1`.
u64 KaslrMaskPointer(u64 p);

/// Recover the real pointer from a previously masked value.
/// Inverse of `KaslrMaskPointer`. Available to in-kernel admin
/// tools that need to display the true address (e.g. a
/// crash-dump analyser running in a trusted context) — never
/// surface this to user space.
u64 KaslrUnmaskPointer(u64 masked);

/// Boot-time self-test: confirms init ran, the candidate is page-
/// aligned, and falls in the documented slide range; also confirms
/// `KaslrPointerMask` is non-zero post-init and that
/// `KaslrUnmaskPointer(KaslrMaskPointer(p)) == p` for a few sample
/// pointers. Logs a single klog line.
void KaslrSelfTest();

} // namespace duetos::security
