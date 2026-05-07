#pragma once

#include "util/types.h"

/*
 * klog persistence — FAT32-backed file sink.
 *
 * Replaces the early-boot tmpfs file sink with a writer that
 * appends every Info+ log line to `KERNEL.LOG` on the FAT32 root
 * volume. Run once after the FAT32 probe, then flushed on the
 * 1 Hz UI tick (compositor scheduler) so a long-uptime log
 * always reflects the current ring within roughly a second.
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
/// "online" line. Returns true if the sink installed; false if
/// no FAT32 volume is mounted or the create failed. Idempotent
/// — a second call truncates and re-installs.
bool KlogPersistInstall();

/// Flush buffered chunks to disk. Call on a low-frequency
/// timer (1 Hz UI tick is plenty) so log lines don't sit in
/// the 4 KiB scratch waiting for it to fill. Safe to call when
/// the sink isn't installed (no-op).
void KlogPersistFlush();

/// True iff the sink is currently installed and pointing at a
/// live FAT32 volume.
bool KlogPersistInstalled();

/// Boot self-test: emits a known marker, flushes, reads back
/// the tail of `KERNEL.LOG`, asserts the marker is present.
/// Skipped if FAT32 isn't mounted or the sink isn't installed.
/// Prints PASS / FAIL / SKIP to COM1.
void KlogPersistSelfTest();

} // namespace duetos::core
