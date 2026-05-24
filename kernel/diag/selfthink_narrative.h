#pragma once

#include "util/types.h"

/*
 * DuetOS — selfthink operator-facing narrative writer.
 *
 * Walks the most recent `SelfPortrait` + causal chain + autonomic-
 * feedback stats and writes a human-readable explanation of the
 * current kernel state to the console. The shape per situation
 * looks like:
 *
 *   Memory is 78% used (heap 82%). MemReclaim fired at tick 18435
 *   with outcome Improved (heap dropped from 82% to 64%). 3 anomalies
 *   observed in the last window: free_frames @ 5000 (mean=12400).
 *
 * Used by the `selfthink why` shell subcommand. The writer is a
 * straight switch-table over CausalKind with per-kind formatters —
 * no template engine, no runtime parsing, no allocation.
 *
 * Context: kernel. Safe from task context only (uses
 * ConsoleWrite); not safe from IRQ context.
 */

namespace duetos::diag::selfthink::narrative
{

/// Write the operator-facing narrative to the kernel console.
/// Single-call entry point; the formatter takes care of the
/// fresh-portrait snapshot and the causal-chain walk internally.
void Write();

/// Boot self-test. Drives the narrative against a known causal
/// chain shape and asserts the writer produces a non-empty
/// header line + at least one section. Emits
/// `[selfthink-narrative] selftest pass` on success.
void SelfTest();

} // namespace duetos::diag::selfthink::narrative
