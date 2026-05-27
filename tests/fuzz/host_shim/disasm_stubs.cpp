// Link stubs for kernel symbols referenced by debug/disasm.cpp's
// formatter/diagnostic path but never reachable from the host
// fuzz drive.
//
// disasm.cpp emits one FixJournal record per decoder-internal
// assertion miss (a defensive invariant the formatter would hit
// if it ever produced an out-of-range width) and resolves any
// computed branch target to a symbol for the operands field.
// The fuzz harness drives DecodeStream on attacker bytes; the
// formatter path is exercised in full, but it never legitimately
// reaches FixJournalRecord (that's a self-healing observer, not
// part of the decode contract), and ResolveAddress on a synthetic
// VA returns "not found" — a stub returning false matches that
// behaviour exactly.

#include "diag/fix_journal.h"
#include "util/symbols.h"
#include "util/result.h"

namespace duetos::diag
{

::duetos::core::Result<void> FixJournalRecord(FixDetector, const char*, const char*, ::duetos::u64, ::duetos::u64)
{
    return {};
}

} // namespace duetos::diag

namespace duetos::core
{

// A real kernel build links symbols_generated.cpp (built from the
// stage-1 link) for the embedded symbol table; on the host
// harness there's no kernel image to symbolize, so the resolver
// always misses. disasm.cpp's caller already handles `false` by
// formatting the bare hex address.
bool ResolveAddress(::duetos::u64, SymbolResolution*)
{
    return false;
}

} // namespace duetos::core
