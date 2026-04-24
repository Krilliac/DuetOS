#pragma once

#include "types.h"

/*
 * DuetOS — embedded kernel symbol table.
 *
 * The kernel ships with a compact, sorted-by-address table that maps
 * runtime instruction pointers back to:
 *
 *   - demangled function name
 *   - source file path (repo-relative, e.g. `kernel/core/panic.cpp`)
 *   - line number where the function is defined
 *   - function start offset
 *
 * The table is produced at build time by `tools/gen-symbols.sh`, which
 * runs against a stage-1 link of the kernel and emits a generated C++
 * file (`symbols_generated.cpp`). The generated file is then linked
 * into the final kernel. See `kernel/CMakeLists.txt` for the two-stage
 * build mechanics.
 *
 * Why embed it rather than parse DWARF at runtime?
 *   - DWARF is too large a surface to decode in a panic path. A single
 *     unmapped page walked into by a DWARF reader would triple-fault
 *     us on top of the crash we're already trying to report.
 *   - Tooling already agrees on "function name + file + line"; that's
 *     the lowest-common-denominator debug unit. Richer DWARF info
 *     (types, inlining) is a post-mortem concern — use the external
 *     `tools/symbolize.sh` for that.
 *
 * All storage lives in `.rodata`. The resolver is allocation-free and
 * safe from panic / IRQ / early-boot context (before the scheduler is
 * online, before paging self-test, before anything).
 *
 * Context: kernel. Thread-safe by construction (read-only rodata).
 */

namespace duetos::core
{

/// One row of the embedded symbol table. Addresses are absolute virtual
/// addresses in the higher-half kernel; sizes are function extents in
/// bytes. `name` and `file` point into the table's own string pool,
/// which lives in the same `.rodata` section and therefore outlives any
/// non-trivial execution.
///
/// Layout is fixed so the generated file can emit a plain brace-list
/// initialiser. Keep this struct in sync with `tools/gen-symbols.sh`.
struct SymbolEntry
{
    u64 addr;         // function entry VA
    u32 size;         // extent in bytes; 0 if unknown
    u32 line;         // line number where the function is defined; 0 if unknown
    const char* name; // demangled symbol name (never null — "??" if unknown)
    const char* file; // repo-relative path (never null — "??" if unknown)
};

/// Result of a successful resolve. `offset` is bytes from `entry->addr`
/// to the queried address.
struct SymbolResolution
{
    const SymbolEntry* entry;
    u64 offset;
};

/// Look up `addr` in the embedded table. Returns true iff a function
/// whose [addr, addr+size) interval contains the query is found.
///
/// A symbol with size == 0 matches only its exact start address — we
/// deliberately don't spread zero-sized symbols over the gap to the
/// next entry, because that would silently misattribute addresses in
/// linker-inserted padding.
///
/// Safe in any context (no allocation, no locks, no syscalls).
bool ResolveAddress(u64 addr, SymbolResolution* out);

/// Number of entries in the embedded table. Diagnostic — a non-zero
/// value confirms the build-time symbol extractor ran. Zero means the
/// kernel was built with the stub (stage-1) symbol table.
u64 SymbolTableSize();

/// Format `resolution` into `[name+0xOFF (path/file.cpp:LINE)]` on
/// COM1. If `resolution.entry` is null (caller didn't resolve, or the
/// resolve failed), emits nothing — callers typically wrap this in a
/// conditional and fall back to plain hex.
void WriteResolvedAddress(const SymbolResolution& resolution);

/// Resolve + emit the decorated form `<hex>  [name+0xOFF (file:line)]`.
/// Fallback: if the address cannot be resolved, emits only `<hex>`.
/// Used by the panic path so every address in the dump is annotated
/// where possible.
void WriteAddressWithSymbol(u64 addr);

} // namespace duetos::core
