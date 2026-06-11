#pragma once

#include "env/autonomic.h" // AutoInputs / AutoActionSet value types

namespace duetos::env
{

/// How the learned policy participates in the decision:
///   Off    — policy disabled; the rule table alone decides.
///   Shadow — net infers and is traced, but actuators stay rule-driven
///            (the safe default: pure data collection, no consequences).
///   Live   — net's gated actions drive the actuators + learn online.
enum class PolicyMode : u8
{
    Off = 0,
    Shadow = 1,
    Live = 2,
};

/// Toggleable safety shield over the learned autonomic policy. Each
/// field gates one safeguard; all default ON. `shields_enabled` is the
/// master — when off, the raw policy drives the actuators directly so
/// an operator can collect un-shielded behaviour during testing.
struct ShieldConfig
{
    bool shields_enabled;   // master — off bypasses the whole envelope
    bool rule_floor_veto;   // rule table can override an unsafe net action
    bool action_clamp;      // actuator parameters stay within safe bounds
    bool circuit_breaker;   // stop an action that repeatedly Worsens
    bool explore_cap;       // bound the epsilon-greedy exploration rate
    bool forbidden_actions; // high-consequence actions stay rule-only
};

/// Every safeguard ON — the production default.
inline constexpr ShieldConfig kShieldDefaults{true, true, true, true, true, true};

/// Flip the whole envelope in one call. `on=false` is the operator
/// master-off ("reel in the data"); `on=true` restores full shielding.
inline void ShieldSetMaster(ShieldConfig& c, bool on)
{
    c.shields_enabled = on;
    c.rule_floor_veto = on;
    c.action_clamp = on;
    c.circuit_breaker = on;
    c.explore_cap = on;
    c.forbidden_actions = on;
}

/// Reconcile the rule floor with the learner's proposal and return the
/// action set that actually reaches the actuators. Slice 1 has no
/// learner, so `net_set` is always empty and the rule floor IS the
/// decision; `cfg`/`in`/`net_set` are the seam later slices reconcile
/// through (net vs floor, clamps, circuit-breaker) — unused here.
inline AutoActionSet ShieldApply(const ShieldConfig& /*cfg*/, const AutoInputs& /*in*/, const AutoActionSet& rule_set,
                                 const AutoActionSet& /*net_set*/)
{
    return rule_set;
}

namespace detail
{

/// True iff `cmdline` contains a whitespace-delimited token exactly
/// equal to `kv` (e.g. "autonomic=live"). Whole-token match, so
/// "autonomicx=live" does NOT match "autonomic=live". nullptr -> false.
/// Freestanding: no libc, so it works in kernel and host builds alike.
inline bool CmdlineHasToken(const char* cmdline, const char* kv)
{
    if (cmdline == nullptr || kv == nullptr)
    {
        return false;
    }
    const char* p = cmdline;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }
        const char* tok_end = p;
        while (*tok_end != '\0' && *tok_end != ' ' && *tok_end != '\t')
        {
            ++tok_end;
        }
        const char* a = p;
        const char* b = kv;
        while (a < tok_end && *b != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (a == tok_end && *b == '\0')
        {
            return true;
        }
        p = tok_end;
    }
    return false;
}

} // namespace detail

/// Parse the `autonomic=off|shadow|live` boot token. Absent/unknown ->
/// the safe default (Shadow). Freestanding (own token scan, not the
/// kernel CmdlineMatches) so the parse contract is host-testable.
inline PolicyMode PolicyModeFromCmdline(const char* cmdline)
{
    if (detail::CmdlineHasToken(cmdline, "autonomic=off"))
    {
        return PolicyMode::Off;
    }
    if (detail::CmdlineHasToken(cmdline, "autonomic=live"))
    {
        return PolicyMode::Live;
    }
    return PolicyMode::Shadow; // "autonomic=shadow" or absent
}

/// Parse the `shields=on|off` boot token. Absent/unknown -> true
/// (shielded). `shields=off` boots straight into un-shielded data
/// collection ("reel in the data").
inline bool ShieldsEnabledFromCmdline(const char* cmdline)
{
    return !detail::CmdlineHasToken(cmdline, "shields=off");
}

// ---------------------------------------------------------------------
// Kernel runtime state (defined in policy_shield.cpp). The pure config
// logic above is host-tested; these own the live singletons the
// PolicyDecide seam reads and the boot cmdline / shell write. Declared
// here (not called by the host test) so the whole shield API is one file.
// ---------------------------------------------------------------------

/// The live shield config the PolicyDecide seam consults each tick.
const ShieldConfig& ShieldConfigGet();

/// Runtime master toggle (the shell `autonomic shields on|off`). Flips
/// the whole envelope on the live config and logs the transition.
void ShieldMasterSet(bool on);

/// The live policy mode the PolicyDecide seam consults each tick.
PolicyMode PolicyModeGet();
void PolicyModeSet(PolicyMode m);
const char* PolicyModeName(PolicyMode m);

/// Parse `autonomic=`/`shields=` from the boot cmdline and apply them to
/// the live config. Call once early in boot (cmdline still mapped).
void PolicyConfigInitFromCmdline(const char* cmdline);

/// Boot self-test: drives the pure config logic (defaults, master toggle
/// round-trip, cmdline parse, ShieldApply passthrough) and emits
/// `[policy-shield] selftest pass`. Panics on mismatch.
void PolicyShieldSelfTest();

} // namespace duetos::env
