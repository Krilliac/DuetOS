#pragma once

#include "security/privilege/arm_state.h"
#include "security/privilege/scope.h"
#include "web/js/interp.h"

/*
 * DuetOS — Privileged-Origin Mode (spec §13.7): the `window.duetos.*` JS
 * host binding. This is the BROWSER client's (Client A) adapter onto the
 * kernel-level Privilege Engine (kernel/security/privilege/): it builds the
 * host-object tree and marshals each method call to
 * security::privilege::ValidateRequest. The pure engine stays JS-free; this
 * one file is the JS bridge.
 *
 * Installed ONLY on an armed tab's JS context (PrivConfig.available &&
 * PrivTab.IsArmed). A non-armed page sees `window.duetos === undefined`.
 */

namespace duetos::web::priv
{
// ---- Executor hooks (Phase 2b) -------------------------------------------
// The privileged binding lives in the JS engine (kernel/web); the actual
// execution helpers (TLS transport, armed-scope -> kCap* mapping) are app-layer
// policy in the browser app. The app registers these function-pointers on the
// PrivBind so the engine can VALIDATE + AUDIT, then DELEGATE — without coupling
// kernel/web to proc/net/TLS. A null hook => that method is validate+audit only
// (no execution): the degradation contract that keeps the self-test mockable
// and avoids any regression while the feature is mid-bring-up.

// Fetch request/response marshalled across the fetch hook. The BINDING owns
// `body` storage: it provides a bounded bounce buffer (`bodyCap`); the executor
// writes up to that and reports `bodyLen`/`status`/`ok`.
struct FetchReq
{
    const char* url = nullptr;
    const char* method = "GET"; // "GET" | "POST"
    const char* body = nullptr; // POST body (may be null)
    duetos::u32 bodyLen = 0;
    const char* contentType = nullptr;
};
struct FetchRes
{
    char* body = nullptr;    // caller-owned buffer (binding provides)
    duetos::u32 bodyCap = 0; // capacity of body
    duetos::u32 bodyLen = 0; // bytes the executor wrote
    duetos::u32 status = 0;  // HTTP status
    bool ok = false;
};

// Spawn executor: read+load `canonPath` from an exec root, spawn with caps
// derived from `armedScope` (child <= broker). Returns child pid (>0) or -errno.
using SpawnExec = duetos::i64 (*)(const char* canonPath, const char* const* argv, duetos::u32 argc,
                                  const duetos::security::privilege::CapSet& armedScope, void* ctx);
// Fetch executor: run `req` over the browser's page-fetch transport. Returns true
// on transport success (out->status/body filled); false on transport/connect fail.
using FetchExec = bool (*)(const FetchReq& req, FetchRes* out, void* ctx);

struct PrivBind
{
    const duetos::security::privilege::PrivTab* tab = nullptr;
    duetos::security::privilege::Roots roots{};
    const char* origin = "https://claude.ai/code";
    const char* client = "browser"; // audit client-identity tag
    SpawnExec spawnExec = nullptr;  // null => proc.spawn validate+audit only
    FetchExec fetchExec = nullptr;  // null => net.fetch  validate+audit only
    void* execCtx = nullptr;        // opaque ctx passed to the executors
};

// Build the `duetos` host object (hostGet exposes armed/origin/scope +
// fs/proc/kernel/net; installHandler is intentionally absent). Returns the
// Object JsValue, or Undefined on arena exhaustion.
js::JsValue BuildDuetosObject(js::Interp& I, PrivBind* bind);

// Define `duetos` + a `window` host object (window.duetos) on I.global.
// Call only when the tab is armed. Returns false if there is no global env.
bool PrivBindingInstall(js::Interp& I, PrivBind* bind);

// Test-only hook: format the current wall clock as "YYYY-MM-DDTHH:MM:SSZ" into
// `out` (cap must be >= 21). Exposed solely so the boot self-test can assert the
// stamp's shape without a mounted FAT32 volume; production code uses the
// internal formatter directly.
void PrivBindingFormatIso8601(char* out, duetos::u32 cap);

void PrivBindingSelfTest();

} // namespace duetos::web::priv
