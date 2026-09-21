#pragma once

#include "util/types.h"

/*
 * klog persistence — FAT32-backed file sink.
 *
 * Replaces the early-boot tmpfs file sink with a bounded atomic
 * producer queue and a process-context writer that routes Info+
 * lines to per-area FAT32 logs. Run once after the FAT32 probe,
 * then flush on the 1 Hz UI tick so a long-uptime log reflects
 * the current queue within roughly a second.
 *
 * Cross-boot retention: on install, KERNEL.LOG ages to KERNEL.0,
 * the existing KERNEL.<i> archive chain shifts down one slot, and
 * the oldest is dropped. A bounded number of past boots (depth
 * == 4 currently) are kept on disk for post-mortem inspection.
 *
 * Mid-boot rotation: when KERNEL.LOG would grow past 256 KiB on
 * the next flush, the same chain shift runs in-place — so a
 * long-running boot doesn't grow the on-disk log unbounded.
 */

namespace duetos::core
{

/// Truncate `KERNEL.LOG` on the FAT32 root, install the FAT32
/// file sink (replaying the current log ring through it so the
/// file captures pre-install Info+ history), and emit one
/// "online" line. Returns true if the sink installed (or was
/// already installed); false if no FAT32 volume is mounted or
/// another installer/consumer currently owns initialization.
bool KlogPersistInstall();

/// Try to drain queued records and flush per-area buffers to disk. Call on a
/// low-frequency timer (1 Hz UI tick is plenty). Returns false only when
/// another process-context caller already owns the single-consumer gate; the
/// queued records remain intact for a later retry. Safe before installation.
bool KlogPersistFlush();

/// True iff the sink is currently installed and pointing at a
/// live FAT32 volume.
bool KlogPersistInstalled();

/// Number of persistence records dropped because the bounded producer queue
/// was full. The serial and in-memory klog copies remain authoritative.
u64 KlogPersistDroppedLines();

/// Boot self-test: emits a known marker, flushes, reads back
/// the tail of `DIAG.LOG`, asserts the marker is present.
/// Skipped if FAT32 isn't mounted or the sink isn't installed.
/// Prints PASS / FAIL / SKIP to COM1.
void KlogPersistSelfTest();

} // namespace duetos::core
