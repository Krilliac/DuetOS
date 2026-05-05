#pragma once

#include "security/fault_domain.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — module lifecycle layer over `core::FaultDomain`.
 *
 * `core::FaultDomain` already owns the registry, the trap-safe
 * `MarkRestart` bool, and the watchdog drain. This file adds the
 * operator-visible verb set the shell uses:
 *
 *   - `ModuleStart(id)` — run init() on a Stopped module.
 *   - `ModuleStop(id)`  — run teardown() on a Running module.
 *   - `ModuleRestart(id)` — teardown + init unconditionally
 *     (forwards to `FaultDomainRestart`).
 *   - `ModuleDump(id)`  — emit a non-fatal per-domain crash record
 *     on serial + ramfs without halting the kernel.
 *   - `ModuleStateOf(id)` — operator-visible `ModuleState`.
 *
 * Every transition fires the `kModuleStateChange` probe so a GDB
 * session can break on every state flip with one breakpoint.
 *
 * The split between this file and `fault_domain.cpp` is purely
 * about API surface: the registry stays minimal for the trap
 * path (which can't take locks), and the operator surface lives
 * here in heartbeat / shell context.
 *
 * Context: kernel. Heartbeat / shell only — never call from a
 * trap handler. The trap path uses `FaultDomainMarkRestart`
 * directly.
 */

namespace duetos::security
{

/// Lookup a domain's current `ModuleState`. Returns
/// `ModuleState::Stopped` for an unregistered id so an operator
/// inspecting an unknown name sees a stable, unambiguous label
/// rather than an error.
::duetos::core::ModuleState ModuleStateOf(::duetos::core::FaultDomainId id);

/// Human-readable label for log lines and shell output.
/// Stable strings; safe to embed in serial dumps without copy.
const char* ModuleStateName(::duetos::core::ModuleState s);

/// Run `init()` on a Stopped or Crashed module. Refuses with
/// `Err{InvalidState}` if the module is currently Running — the
/// operator should `module restart` instead. On success the
/// module's state becomes `Running` and `alive` flips to true.
/// Returns the underlying init's Err on failure.
::duetos::core::Result<void> ModuleStart(::duetos::core::FaultDomainId id);

/// Run `teardown()` on a Running or Crashed module. Refuses with
/// `Err{InvalidState}` if the module is currently Stopped (a no-op
/// would be a footgun — operator probably typed the wrong name).
/// On success the module's state becomes `Stopped` and `alive`
/// flips to false. Returns the underlying teardown's Err on
/// failure.
::duetos::core::Result<void> ModuleStop(::duetos::core::FaultDomainId id);

/// Drive teardown + init unconditionally. Thin wrapper over
/// `core::FaultDomainRestart` so callers can use a uniform
/// `module` verb regardless of current state.
::duetos::core::Result<void> ModuleRestart(::duetos::core::FaultDomainId id);

/// Emit a non-fatal per-domain crash record on serial AND the
/// ramfs ring at `/var/crash/<sanitized-name>.dump`, without
/// halting the kernel. Returns `Err{NotFound}` for an invalid
/// id. Safe to call regardless of module state — useful even
/// for a Running module if an operator wants a triage snapshot.
::duetos::core::Result<void> ModuleDump(::duetos::core::FaultDomainId id);

/// Boot-time self-test. Registers a synthetic module, exercises
/// Stop → Start → Restart → Dump, asserts every state transition
/// and every refusal path. Panics on mismatch.
void ModuleSelfTest();

} // namespace duetos::security
