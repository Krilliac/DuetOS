#pragma once

#include "diag/selfthink.h"
#include "util/types.h"

/*
 * DuetOS — selfthink cross-boot persistence (FAT32 tier-1).
 *
 * Mirrors the in-RAM causal-chain ring to `/KERNEL.THK` on the
 * FAT32 root volume so a reviewer can pull the recent events from
 * the PRIOR boot after a reset — exactly the post-mortem case the
 * runtime probe + autonomic-feedback output is most useful in.
 *
 * On-disk format:
 *
 *   [u32 magic 'STHK' (little-endian)]
 *   [u32 version (= 1)]
 *   [u32 entry_count]
 *   [u32 reserved]
 *   [CausalEntry × entry_count]
 *
 * Persistence model:
 *
 *   * Install (boot, post-FAT32-mount):
 *     1. Read existing KERNEL.THK into the in-RAM "prior boot"
 *        buffer. If the file is absent / invalid / for an
 *        incompatible version, the buffer stays empty.
 *     2. Delete + recreate an empty KERNEL.THK so the periodic
 *        flush has a fresh canvas.
 *   * Periodic flush (kselfthink wake, post-bringup): rewrite
 *     KERNEL.THK from the live causal ring + a header. Bounded:
 *     1024 entries × 48 B + 16 B header ≈ 48.4 KiB. Comfortable
 *     under FAT32 throughput budget at 1 Hz cadence.
 *
 * Single-backup scheme — only the immediately previous boot is
 * retained. fix_journal_persist's N-deep rotation isn't justified
 * here: the causal chain is for "what did the kernel just do?"
 * triage, not the long-tail "is this gap chronic across many
 * boots?" question that the fix journal answers.
 *
 * Tier-2 (NVMe panic write) is a follow-up — the FAT32 tier is
 * sufficient for clean-reboot post-mortems, and adding the NVMe
 * mirror requires its own panic-safety audit that this slice
 * does not attempt.
 *
 * Context: kernel. Install + flush MUST run in task context (FAT32
 * helpers take internal locks; not safe from IRQ).
 */

namespace duetos::diag::selfthink::persist
{

constexpr u32 kPersistMagic = 0x4B485453; // 'STHK' little-endian
constexpr u32 kPersistVersion = 1;
constexpr const char* kPersistPath = "KERNEL.THK";

/// Install the FAT32 sink. Reads the existing KERNEL.THK into the
/// in-RAM prior-boot buffer (best effort), then truncates the file
/// to an empty fresh canvas. Idempotent on repeat calls — a second
/// install reads back what we just wrote (empty) so the prior
/// buffer survives in-RAM.
///
/// Safe to call when no FAT32 volume is mounted — the prior buffer
/// stays empty + the periodic flush becomes a no-op.
void Install();

/// Rewrite KERNEL.THK from the current in-RAM causal ring. No-op
/// when the sink isn't installed or no FAT32 volume is mounted.
/// Safe to call on the kselfthink wake cadence.
void Flush();

/// True iff the install path saw a FAT32 volume and the prior
/// buffer is at least partially populated. Used by `selfthink prev`
/// to print "(no prior boot data)" cleanly when this is the first
/// boot.
bool PriorAvailable();

/// Number of entries restored from the prior KERNEL.THK. Bounded
/// at kCausalRingCap; equal to the prior boot's entry_count
/// header field on a successful restore.
u32 PriorEntryCount();

/// Walk the prior-boot ring newest-first, invoking `cb`. Used by
/// `selfthink prev causality`. Returns entries visited.
u32 PriorRingWalk(bool (*cb)(const CausalEntry& e, void* ctx), void* ctx);

/// Boot self-test. Round-trips a single sentinel causal entry
/// through serialize → parse → assert match. Emits
/// `[selfthink-persist] selftest pass` on success; SKIP when no
/// FAT32 volume is mounted.
void SelfTest();

} // namespace duetos::diag::selfthink::persist
