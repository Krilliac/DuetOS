#pragma once

#include "util/types.h"

/*
 * KPath — Tier-2 persistence (FAT32 file).
 *
 * Writes the live ledger to `/KERNEL.KPATH.TSV` on the FAT32
 * root volume so an offline diff tool (tools/test/kpath-coverage.sh)
 * can compare two boots' coverage.
 *
 * On-disk format is plain UTF-8 TSV — same content as the shell
 * `kpath dump` output:
 *
 *   # kpath TSV v1
 *   # fields: category    name    hits    file    line    syscall vector
 *   syscall syscall 12      kernel/syscall/syscall.cpp 0   1       -
 *   ...
 *
 * Why TSV (not binary): KPath is meant to be consumed by humans
 * and grep — the diff tool is a shell script. Going through a
 * binary record format would just add a parser. The KPath ledger
 * is not on-the-hot-path, and `Fat32CreateAtPath` accepts an
 * arbitrary byte buffer regardless of content.
 *
 * Context: kernel. `KPathPersistInstall` MUST run AFTER the
 * FAT32 volume is probed.
 */

namespace duetos::diag
{

constexpr const char* kKPathTsvPath = "KERNEL.KPATH.TSV";

/// Install the sink. Verifies the FAT32 volume is mounted; if so
/// writes the current ledger snapshot and arms the periodic flush
/// trigger. Idempotent — a second call rewrites the file.
bool KPathPersistInstall();

/// Rewrite KERNEL.KPATH.TSV from the current ledger snapshot.
/// No-op when the sink isn't installed. Safe to call from the
/// heartbeat tick or the smoke-completion path.
void KPathPersistFlush();

/// Panic-safe variant. Skips klog, skips the heartbeat hook,
/// uses the panic-safe ledger walk. Same TSV format.
void KPathPersistFlushPanicSafe();

/// True iff the sink is currently installed.
bool KPathPersistInstalled();

} // namespace duetos::diag
