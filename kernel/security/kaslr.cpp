/*
 * DuetOS — KASLR scaffolding implementation.
 *
 * See kaslr.h for the contract. This TU computes a candidate
 * slide and stores it; the slide-application step is a follow-on.
 */

#include "security/kaslr.h"

#include "core/panic.h"
#include "log/klog.h"
#include "util/build_config.h"
#include "util/random.h"

namespace duetos::security
{

namespace
{

// Slide range. Bounded so the slid kernel still fits in the
// canonical high half (top 2 GiB above `0xFFFFFFFF80000000`).
// 21-bit slide => 2 MiB granularity * 512 = up to ~1 GiB of jitter,
// which is plenty (Linux uses ~1 GiB on x86_64). 2 MiB alignment
// keeps the slid kernel landing on a PD boundary so the kernel-
// half page tables don't need split.
constexpr u64 kSlideAlignment = 2ull * 1024 * 1024; // 2 MiB
constexpr u64 kSlideMaxSlots = 512;                 // 1 GiB total range

bool g_initialized = false;
u64 g_candidate_slide = 0;

// Per-boot 64-bit pointer-obfuscation mask. Derived from a fresh
// RandomU64() draw (independent of the candidate-slide draw so a
// leak of the slide doesn't help recover the mask). Initialized
// in `KaslrInit` after `g_candidate_slide`.
u64 g_pointer_mask = 0;

} // namespace

void KaslrInit()
{
    if (g_initialized)
    {
        return;
    }

    if (!core::kKaslrEnabled)
    {
        // Explicit "off" build — candidate stays 0. We still mark
        // init as done so KaslrInitialized() can answer truthfully
        // and the self-test runs cleanly.
        g_initialized = true;
        KLOG_INFO("security/kaslr", "KASLR disabled at compile time (DUETOS_KASLR=0)");
        return;
    }

    // Pull a uniform 64-bit value and reduce it to a slot index
    // by modulo. Modulo bias on a 64-bit input with a 512-slot
    // output is negligible (~10^-17), so plain modulo is fine.
    const u64 raw = core::RandomU64();
    const u64 slot = raw % kSlideMaxSlots;
    g_candidate_slide = slot * kSlideAlignment;
    // Init-time postcondition. The KASLR self-test below verifies
    // the same invariants but runs LATER; pinning them at the
    // produce-site catches a regression (slot math, alignment
    // mismatch) before the slide is published — the self-test only
    // logs warnings, but this is the value that will eventually be
    // applied to real kernel relocations.
    KASSERT_WITH_VALUE((g_candidate_slide & (kSlideAlignment - 1)) == 0, "security/kaslr",
                       "candidate slide not 2-MiB aligned at init", g_candidate_slide);
    KASSERT_WITH_VALUE(g_candidate_slide < kSlideAlignment * kSlideMaxSlots, "security/kaslr",
                       "candidate slide exceeds slot range at init", g_candidate_slide);

    // Pointer-obfuscation mask. Fresh RandomU64 draw — kept
    // independent of g_candidate_slide so a leak of one half
    // doesn't help recover the other. Masked off the high 16
    // bits (canonical x86_64 high half) so an obfuscated value
    // can't accidentally look like a real kernel address.
    g_pointer_mask = core::RandomU64() & 0x0000FFFFFFFFFFFFULL;

    g_initialized = true;

    KLOG_INFO_V("security/kaslr", "KASLR candidate slide computed", g_candidate_slide);
    // Today: the slide is NOT applied to the kernel image. See
    // wiki/security/Linux-CVE-Audit.md class II. The follow-on
    // slice that applies relocations against this slide flips
    // KaslrGetKernelSlide() to return g_candidate_slide.
}

u64 KaslrGetKernelSlide()
{
    // Until the slide-application stub lands, the actual applied
    // slide is 0. Callers that decode kernel addresses can rely
    // on this being correct, so flipping the slide on later is
    // a one-line change in this TU plus the boot-stub change.
    return 0;
}

u64 KaslrGetCandidateSlide()
{
    return g_candidate_slide;
}

bool KaslrInitialized()
{
    return g_initialized;
}

u64 KaslrPointerMask()
{
    return g_pointer_mask;
}

u64 KaslrMaskPointer(u64 p)
{
    return p ^ g_pointer_mask;
}

u64 KaslrUnmaskPointer(u64 masked)
{
    return masked ^ g_pointer_mask;
}

void KaslrSelfTest()
{
    if (!g_initialized)
    {
        KLOG_WARN("security/kaslr", "self-test before KaslrInit");
        return;
    }
    // Candidate must be page-aligned.
    if ((g_candidate_slide & (kSlideAlignment - 1)) != 0)
    {
        KLOG_WARN_V("security/kaslr", "candidate slide is not 2-MiB-aligned", g_candidate_slide);
        return;
    }
    // Candidate must be within the documented range.
    if (g_candidate_slide >= kSlideAlignment * kSlideMaxSlots)
    {
        KLOG_WARN_V("security/kaslr", "candidate slide exceeds slot range", g_candidate_slide);
        return;
    }
    // Pointer mask must be non-zero post-init — if it ever lands
    // as zero, KaslrMaskPointer becomes the identity and the
    // defense is silently disabled. With a 48-bit random draw,
    // the all-zero outcome is 2^-48 — vanishingly rare, but the
    // self-test is the cheapest place to catch it.
    if (g_pointer_mask == 0)
    {
        KLOG_WARN("security/kaslr", "pointer mask landed at zero — RandomU64 broken?");
        return;
    }
    // Mask must reside in the canonical low-half: high 16 bits
    // clear so the obfuscated form cannot accidentally resemble
    // a kernel address.
    if ((g_pointer_mask & 0xFFFF000000000000ULL) != 0)
    {
        KLOG_WARN_V("security/kaslr", "pointer mask escaped low-48-bit window", g_pointer_mask);
        return;
    }
    // Round-trip a handful of representative pointers.
    constexpr u64 kSamples[] = {
        0xFFFFFFFF80000000ULL, // kernel image base
        0xFFFFFFFF80123456ULL, // arbitrary kernel pointer
        0x0000000000400000ULL, // user-space-ish
        0x0ULL,                // edge: zero
        0xFFFFFFFFFFFFFFFFULL, // edge: all ones
    };
    for (u64 p : kSamples)
    {
        if (KaslrUnmaskPointer(KaslrMaskPointer(p)) != p)
        {
            KLOG_WARN_V("security/kaslr", "mask round-trip failed", p);
            return;
        }
    }
    KLOG_INFO("security/kaslr", "self-test OK");
}

} // namespace duetos::security
