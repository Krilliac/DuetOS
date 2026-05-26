#pragma once

#include "util/types.h"

/*
 * DuetOS — static API-set contract → host DLL mapping.
 *
 * Background: an API set (Windows-shaped) is a *contract* DLL
 * name of the form `api-ms-win-<category>-<subcategory>-l<N>-<M>.dll`
 * (or `ext-ms-win-...` for extension sets). No such file exists on
 * disk — the loader is expected to rewrite the contract at bind
 * time to the real "host" DLL that exports the named function
 * (typically `kernelbase.dll`, `kernel32.dll`, or `ntdll.dll`).
 * Windows publishes the schema as a parseable blob in
 * `apisetschema.dll`; we don't load Microsoft binaries at runtime,
 * so this TU is the static stand-in.
 *
 * Why this exists (v1): until this lands, the PE loader's api-set
 * fallback (`TryResolveViaPreloadedDllsAnyName`, pe_loader.cpp ~1613)
 * is a "first preloaded export by name wins" heuristic. For the
 * api-set surface that is unambiguous *in practice* (each contract
 * function is exported by exactly one base DLL), so the heuristic
 * works — but it bakes in a silent collision risk and the boot log
 * carries no indication of WHICH base DLL ended up hosting each
 * import. The static table replaces the heuristic with a
 * deterministic, reviewable mapping; unknown contracts still fall
 * through to the heuristic so behaviour is monotonically better.
 *
 * Update policy: a new contract gets added to the table the first
 * time a real PE imports it. The list is intentionally curated —
 * not every published api-set ships, only the ones the PE corpus
 * actually pulls in. Keep entries sorted by contract head (sans
 * trailing "-N-N.dll") for binary search.
 *
 * Source for the published mapping: Microsoft Learn — "API set
 * loader operation"; Geoff Chappell's ApiSetSchema reference;
 * Wine's `dlls/ntdll/loader.c::get_apiset_target` matching shape;
 * ReactOS `sdk/lib/apisets/`.
 *
 * Subsystem isolation: this is kernel-owned. Userland DLLs do
 * not see the table; they call import names that the PE loader
 * resolves THROUGH this table when assembling per-process IAT
 * patches. Cap-gating is not relevant — the resolution is read-
 * only metadata access during process spawn.
 */

namespace duetos::loader
{

/// Look up an api-set contract's host DLL via the static table.
///
/// `contract` is the raw import name (e.g.
/// `"api-ms-win-core-libraryloader-l1-2-0.dll"`). The function:
///
///   1. Lower-cases the head (the parser is case-insensitive
///      because Windows imports are case-insensitive).
///   2. Strips the trailing `-<major>-<minor>.dll` (or
///      `.dll`-only — both are accepted) so a versioned contract
///      matches the head-only table entries.
///   3. Binary-searches the table.
///   4. On hit, writes the host DLL pointer to `*out_host` (the
///      pointer is a static C string, NOT owned by the caller —
///      do not free) and returns `true`.
///   5. On miss returns `false` without touching `*out_host`.
///
/// The host pointer (when returned) is a NUL-terminated ASCII
/// string with the canonical form (e.g. `"kernelbase.dll"`).
/// Use it to retry `TryResolveViaPreloadedDlls(host, fn_name, ...)`
/// in the loader; the heuristic stays available as a fallback for
/// contracts the table doesn't yet know.
bool ApiSetResolveStatic(const char* contract, const char** out_host);

/// Boot-time self-test. Validates that:
///   - Every table entry is sorted in case-folded order.
///   - Lookup of a known contract returns the expected host.
///   - Lookup of an unknown contract returns false without
///     scribbling the out param.
///   - Versioned suffixes ("-1-0.dll") are correctly stripped.
/// Emits `[apiset-selftest] PASS` on success; panics on failure.
void ApiSetSelfTest();

} // namespace duetos::loader
