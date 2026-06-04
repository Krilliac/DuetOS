#pragma once

#include "security/privilege/scope.h"
#include "util/types.h"
#include "web/priv_binding.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §6 / Phase 2b): the app-layer
 * EXECUTORS the privileged JS binding (kernel/web/priv_binding.h) delegates to
 * after it has VALIDATED + AUDITED a `window.duetos.*` request.
 *
 * The binding stays kernel/web-internal and JS-free; these two executors are
 * the browser app's policy adapters that actually perform the effect:
 *
 *   - PrivSpawnExec — read+load `canonPath` from FAT32, derive the child's
 *                     kernel cap-set strictly from the armed scope (child caps
 *                     are a SUBSET of the broker's armed bits — never trusted),
 *                     and spawn the PE / ELF. Defined here (priv_exec.cpp).
 *
 *   - PrivFetchExec — run a brokered fetch over the browser's page-fetch
 *                     transport. DEFINED in browser.cpp (not here): it reuses a
 *                     file-static TLS-transport helper (`OpenTransport`) that is
 *                     private to that TU, so the definition lives alongside it.
 *                     Declared here only so the registration site has the
 *                     prototype.
 *
 * The function-pointer shapes (SpawnExec / FetchExec) and the FetchReq /
 * FetchRes marshalling structs are the contract committed in
 * kernel/web/priv_binding.h.
 */

namespace duetos::apps::browser
{

// Spawn executor (defined in priv_exec.cpp). Reads `canonPath` from FAT32
// volume 0, derives the child cap-set from `armedScope`, and spawns the
// PE / ELF image. Returns the child pid (> 0) on success, or a negative
// errno (-EIO / -ENOENT / -EINVAL / -ENOMEM / -ENOEXEC) on failure.
duetos::i64 PrivSpawnExec(const char* canonPath, const char* const* argv, duetos::u32 argc,
                          const duetos::security::privilege::CapSet& armedScope, void* ctx);

// Fetch executor — DEFINED in browser.cpp (reuses that TU's file-static
// OpenTransport TLS helper). Declared here only for the registration site.
bool PrivFetchExec(const duetos::web::priv::FetchReq& req, duetos::web::priv::FetchRes* out, void* ctx);

} // namespace duetos::apps::browser
