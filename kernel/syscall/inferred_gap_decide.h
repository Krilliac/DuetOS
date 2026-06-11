#pragma once

// Freestanding decision logic for runtime gap inference (Phase A of the
// dynamic fix-discovery system — see
// docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md).
//
// Split into a header with no kernel dependencies so the hosted unit test
// (tests/host/test_inferred_gap.cpp) can link it directly. The kernel-side
// recorder (inferred_gap.cpp) includes this and adds the FixJournal write.

namespace duetos::syscall
{

// The native "recognized but unimplemented" return value
// (STATUS_NOT_IMPLEMENTED). MUST stay equal to kStatusNotImplemented in
// kernel/syscall/syscall.cpp — a static_assert in inferred_gap.cpp binds them.
inline constexpr unsigned long long kInferredGapSentinel = 0xC0000002ULL;

// True iff a guest received the not-implemented sentinel for a RECOGNIZED
// syscall — the single case worth recording as a discovered gap. A success
// (0), or any *correct* error such as STATUS_ACCESS_DENIED (0xC0000022) or
// STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034), is not a gap and must not record.
constexpr bool InferredGapShouldRecord(unsigned long long rax_value)
{
    return rax_value == kInferredGapSentinel;
}

} // namespace duetos::syscall
