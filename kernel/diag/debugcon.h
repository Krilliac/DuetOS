#pragma once

#include "util/types.h"

/*
 * Binary debug-console writer (Bochs / QEMU port 0xE9).
 *
 * Used as the egress channel for binary crash artefacts whose
 * shape is not text and cannot be reasonably wedged into COM1's
 * ASCII stream. The classic case is a Windows minidump: a
 * structured binary blob that any external debugger (Visual
 * Studio, WinDbg, VSCode-cppvsdbg, dotnet-dump, …) loads
 * directly as a .dmp file.
 *
 * Transport notes:
 *   - QEMU exposes port 0xE9 via `-debugcon file:<path>`. Every
 *     byte written to the port is appended to <path> on the
 *     host side. The guest-side cost is a single OUTB per byte.
 *   - Without `-debugcon`, the OUTB goes nowhere (port 0xE9 is
 *     unassigned on real PCs). Safe to call unconditionally; on
 *     bare metal it's a silent no-op.
 *   - No flow control. The writer is meant for one-shot artefact
 *     emission on a halted CPU, not streaming output.
 *
 * Context: kernel. Allocation-free. Safe from panic / IRQ / trap
 * context — the only operation is `outb 0xE9, %al`.
 */

namespace duetos::diag::debugcon
{

/// Write a single byte to port 0xE9. Routes to the host file
/// configured by QEMU's `-debugcon file:<path>` flag. No-op on
/// hardware that doesn't have a debug console wired to that port.
void WriteByte(u8 byte);

/// Write `len` bytes from `buf` sequentially. Convenience wrapper
/// around per-byte WriteByte; cost is linear in `len`.
void Write(const u8* buf, u64 len);

} // namespace duetos::diag::debugcon
