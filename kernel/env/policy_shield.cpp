#include "env/policy_shield.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

/*
 * Runtime state owner for the autonomic policy shield. The pure config
 * logic (ShieldConfig / ShieldSetMaster / ShieldApply / cmdline parse)
 * lives in the header and is host-tested (tests/host/test_policy_shield.cpp);
 * this TU owns the live singletons the PolicyDecide seam reads and the
 * boot cmdline / shell write, plus the boot self-test.
 *
 * Context: kernel task context. The config is a pair of scalars owned by
 * the single env-monitor task — no lock needed.
 */

namespace duetos::env
{

namespace
{

constinit ShieldConfig g_shield_cfg = kShieldDefaults;
constinit PolicyMode g_policy_mode = PolicyMode::Shadow;

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    arch::SerialWrite("[policy-shield] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    core::PanicWithValue("env/policy_shield", "policy-shield self-test mismatch", 0);
}

} // namespace

const ShieldConfig& ShieldConfigGet()
{
    return g_shield_cfg;
}

void ShieldMasterSet(bool on)
{
    ShieldSetMaster(g_shield_cfg, on);
    if (on)
    {
        KLOG_INFO("policy", "shield master ON — full safety envelope");
    }
    else
    {
        KLOG_WARN("policy", "shield master OFF — raw policy drives actuators (data-collection mode)");
    }
}

PolicyMode PolicyModeGet()
{
    return g_policy_mode;
}

void PolicyModeSet(PolicyMode m)
{
    g_policy_mode = m;
    KLOG_INFO_S("policy", "mode set", "to", PolicyModeName(m));
}

const char* PolicyModeName(PolicyMode m)
{
    switch (m)
    {
    case PolicyMode::Off:
        return "off";
    case PolicyMode::Shadow:
        return "shadow";
    case PolicyMode::Live:
        return "live";
    }
    return "?";
}

void PolicyConfigInitFromCmdline(const char* cmdline)
{
    g_policy_mode = PolicyModeFromCmdline(cmdline);
    ShieldSetMaster(g_shield_cfg, ShieldsEnabledFromCmdline(cmdline));
    KLOG_INFO_S("policy", "config from cmdline", "mode", PolicyModeName(g_policy_mode));
    if (!g_shield_cfg.shields_enabled)
    {
        KLOG_WARN("policy", "shields DISABLED via cmdline — un-shielded policy data collection");
    }
}

void PolicyShieldSelfTest()
{
    // Defaults: every safeguard ON.
    Expect(kShieldDefaults.shields_enabled && kShieldDefaults.rule_floor_veto && kShieldDefaults.action_clamp &&
               kShieldDefaults.circuit_breaker && kShieldDefaults.explore_cap && kShieldDefaults.forbidden_actions,
           "defaults all on");

    // Master toggle round-trip — off clears EVERY safeguard, on restores.
    ShieldConfig c = kShieldDefaults;
    ShieldSetMaster(c, false);
    Expect(!c.shields_enabled && !c.rule_floor_veto && !c.action_clamp && !c.circuit_breaker && !c.explore_cap &&
               !c.forbidden_actions,
           "master off clears all");
    ShieldSetMaster(c, true);
    Expect(c.shields_enabled && c.forbidden_actions, "master on restores");

    // Cmdline parse contract.
    Expect(PolicyModeFromCmdline("autonomic=live") == PolicyMode::Live, "cmdline mode live");
    Expect(PolicyModeFromCmdline(nullptr) == PolicyMode::Shadow, "cmdline default shadow");
    Expect(!ShieldsEnabledFromCmdline("shields=off"), "cmdline shields off");
    Expect(ShieldsEnabledFromCmdline(nullptr), "cmdline shields default on");

    // ShieldApply: empty net -> rule floor passes through (Slice 1).
    AutoActionSet rules = {};
    rules.count = 1;
    rules.actions[0] = AutoAction::MemReclaim;
    const AutoActionSet net = {};
    const AutoInputs in = {};
    const AutoActionSet out = ShieldApply(g_shield_cfg, in, rules, net);
    Expect(out.count == 1 && out.actions[0] == AutoAction::MemReclaim, "shieldapply passthrough");

    arch::SerialWrite("[policy-shield] selftest pass\n");
}

} // namespace duetos::env
