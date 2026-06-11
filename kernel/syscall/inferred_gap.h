#pragma once

#include "util/types.h"

// Phase A of dynamic fix-discovery: record an InferredGap fix-journal entry
// when a guest receives the not-implemented sentinel for a recognized syscall.
// Called once from the SyscallDispatch return path. See
// docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md.

namespace duetos::syscall
{

// Per-boot cap on DISTINCT inferred-gap pins. Public so the Phase B config-
// proposal allow-list (kernel/env/config_proposal.cpp) can static_assert its
// mirrored value against this one — they must not drift.
inline constexpr u32 kInferredGapPinCap = 128;

// If `rax_value` is the not-implemented sentinel, record (dedup-per-number) an
// InferredGap journal entry keyed by `syscall:0x<num>`. No-op otherwise and
// once the per-boot distinct-pin cap is reached. Cheap on the common path
// (single compare) so it is safe to call on every syscall return.
void InferredGapMaybeRecord(u64 rax_value, u64 syscall_number);

// Number of distinct inferred-gap pins dropped this boot because the per-boot
// cap was reached. The Phase B learner reads this as evidence to propose
// raising kInferredGapPinCap. 0 on a healthy boot.
u32 InferredGapDroppedCount();

} // namespace duetos::syscall
