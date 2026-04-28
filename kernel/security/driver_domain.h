#pragma once

#include "security/fault_domain.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — per-driver fault-domain extension, v0 (plan E3).
 *
 * WHAT
 *   A thin convention layer over `core::FaultDomain*` for the
 *   "per-driver" use case. Drivers call
 *   `RegisterDriverDomain(name, init, teardown)` at init time;
 *   the registry exposes `RestartDriverDomain(name)` to the
 *   shell for "kick a driver without rebooting" scenarios.
 *
 * WHY THIS, NOT JUST FaultDomain DIRECT
 *   FaultDomainRegister already takes (name, init, teardown).
 *   This wrapper adds three things: (a) a stable
 *   "driver-domain" tag for diagnostic filtering, (b) a count
 *   accessor so a future health scan can answer "how many
 *   driver domains are live", (c) a shell-friendly Restart
 *   wrapper that resolves the name lookup.
 *
 * SCOPE FOR v0
 *   - Wrapper API + a self-test that registers a synthetic
 *     driver domain, restarts it, and asserts the
 *     init/teardown counters advanced.
 *   - No automatic registration of existing drivers — each
 *     driver opts in by calling `RegisterDriverDomain` from
 *     its own Init code in a future slice.
 */

namespace duetos::security
{

/// Register a driver fault domain. Returns the assigned id, or
/// `core::kFaultDomainInvalid` on failure (registry full / null
/// args). Forwards to `core::FaultDomainRegister`; difference
/// is the convention that callers pass driver-specific
/// init/teardown closures.
core::FaultDomainId RegisterDriverDomain(const char* name, ::duetos::core::Result<void> (*init)(),
                                         ::duetos::core::Result<void> (*teardown)());

/// Restart a driver domain by name. Returns Ok on success or
/// `Err{ErrorCode::NotFound}` when no domain matches.
/// Logs a one-line "[driver-domain] restart: <name>" message
/// regardless of outcome.
::duetos::core::Result<void> RestartDriverDomain(const char* name);

/// Count of driver-domain registrations since boot. Cheap u32.
u32 DriverDomainCount();

/// Boot-time self-test. Registers a synthetic driver domain
/// with init + teardown hooks that bump file-scope counters,
/// drives Restart twice, asserts each counter advanced by 2.
/// Panics on mismatch.
void DriverDomainSelfTest();

} // namespace duetos::security
