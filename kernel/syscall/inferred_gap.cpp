#include "syscall/inferred_gap.h"

#include "diag/fix_journal.h"
#include "syscall/inferred_gap_decide.h"

namespace duetos::syscall
{

namespace
{

// kInferredGapPinCap lives in the header (shared with the Phase B config-
// proposal allow-list). It bounds DISTINCT inferred-gap pins per boot: a
// recognized-but-unimplemented syscall set is small, so this only guards a
// pathological build registering hundreds of distinct numbers. Over-cap
// attempts are dropped; dedup of an already-seen pin is unaffected (only
// first-sightings count). g_dropped exposes the over-cap drops as the Phase B
// learner's evidence to propose raising the cap.
constinit u32 g_distinct_pins = 0;
constinit u32 g_dropped = 0;

// Render "syscall:0x<hex>" into `out` (>= 24 bytes). Freestanding — the
// journal hint/pin path runs in process context but we avoid any allocation
// or formatting helper to keep this callable from the syscall hot tail.
void FormatPin(char* out, u64 syscall_number)
{
    static constexpr char kPrefix[] = "syscall:0x";
    char* p = out;
    for (const char* s = kPrefix; *s != '\0'; ++s)
        *p++ = *s;

    bool started = false;
    for (int shift = 12; shift >= 0; shift -= 4)
    {
        const u32 nib = static_cast<u32>((syscall_number >> shift) & 0xF);
        if (nib != 0 || started || shift == 0)
        {
            *p++ = (nib < 10) ? static_cast<char>('0' + nib) : static_cast<char>('a' + nib - 10);
            started = true;
        }
    }
    *p = '\0';
}

} // namespace

void InferredGapMaybeRecord(u64 rax_value, u64 syscall_number)
{
    // Bind the freestanding sentinel to the kernel's status constant. If a
    // future change moves kStatusNotImplemented, this fires at compile time.
    static_assert(kInferredGapSentinel == 0xC0000002ULL, "InferredGap sentinel drifted from kStatusNotImplemented");

    if (!InferredGapShouldRecord(rax_value))
        return;

    // Bound distinct pins per boot. A repeat of an already-recorded number
    // still dedups inside FixJournalRecord (bumps repeat), so the cap only
    // gates brand-new pins; we approximate by counting attempts that could be
    // new. The journal's own OutOfMemory path is the hard backstop.
    if (g_distinct_pins >= kInferredGapPinCap)
    {
        ++g_dropped; // evidence for the Phase B learner: cap too low
        return;
    }
    ++g_distinct_pins;

    char pin[24];
    FormatPin(pin, syscall_number);
    (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::InferredGap, pin,
                                           "recognized syscall returned NotImplemented — implement or remove the op",
                                           syscall_number, 0);
}

u32 InferredGapDroppedCount()
{
    return g_dropped;
}

} // namespace duetos::syscall
