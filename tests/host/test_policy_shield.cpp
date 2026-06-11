// tests/host/test_policy_shield.cpp
//
// Hosted unit tests for kernel/env/policy_shield.h — the toggleable
// safety shield that gates the learned autonomic policy's actions
// before they reach the kernel actuators.
//
// Slice 1 pins (this file grows as the slice does):
//   - ShieldConfig defaults: every safeguard ON.
//   - ShieldSetMaster(cfg, false) clears EVERY safeguard in one call —
//     the operator-facing master-off used to collect un-shielded data
//     during testing ("fully reel in the data").
//   - ShieldSetMaster(cfg, true) restores every safeguard.
//
// The shield core is freestanding (plain value types), so the whole
// contract is host-testable without a kernel build.

#include "host_test_helper.h"

#include "env/autonomic.h"
#include "env/policy_shield.h"

using duetos::u32;
using duetos::env::AutoAction;
using duetos::env::AutoActionSet;
using duetos::env::AutoInputs;
using duetos::env::AutoRule;
using duetos::env::kShieldDefaults;
using duetos::env::PolicyMode;
using duetos::env::PolicyModeFromCmdline;
using duetos::env::ShieldApply;
using duetos::env::ShieldConfig;
using duetos::env::ShieldReconcile;
using duetos::env::ShieldsEnabledFromCmdline;
using duetos::env::ShieldSetMaster;

int main()
{
    // ----- Defaults: every safeguard ON -------------------------
    {
        ShieldConfig c = kShieldDefaults;
        EXPECT_TRUE(c.shields_enabled);
        EXPECT_TRUE(c.rule_floor_veto);
        EXPECT_TRUE(c.action_clamp);
        EXPECT_TRUE(c.circuit_breaker);
        EXPECT_TRUE(c.explore_cap);
        EXPECT_TRUE(c.forbidden_actions);
    }

    // ----- Master OFF clears every safeguard in one call --------
    {
        ShieldConfig c = kShieldDefaults;
        ShieldSetMaster(c, false);
        EXPECT_FALSE(c.shields_enabled);
        EXPECT_FALSE(c.rule_floor_veto);
        EXPECT_FALSE(c.action_clamp);
        EXPECT_FALSE(c.circuit_breaker);
        EXPECT_FALSE(c.explore_cap);
        EXPECT_FALSE(c.forbidden_actions);
    }

    // ----- Master ON restores every safeguard -------------------
    {
        ShieldConfig c = kShieldDefaults;
        ShieldSetMaster(c, false);
        ShieldSetMaster(c, true);
        EXPECT_TRUE(c.shields_enabled);
        EXPECT_TRUE(c.rule_floor_veto);
        EXPECT_TRUE(c.action_clamp);
        EXPECT_TRUE(c.circuit_breaker);
        EXPECT_TRUE(c.explore_cap);
        EXPECT_TRUE(c.forbidden_actions);
    }

    // ----- ShieldApply: empty net -> rule set passes through ----
    // Slice 1 has no neural net, so net_set is always empty and the
    // shield must hand the rule floor through unchanged — shields on
    // OR off (there is nothing to gate without a learner).
    {
        AutoActionSet rules = {};
        rules.count = 1;
        rules.actions[0] = AutoAction::MemReclaim;
        rules.rules[0] = AutoRule::MemPressure;
        const AutoActionSet net = {}; // empty (no learner in Slice 1)
        const AutoInputs in = {};

        ShieldConfig c = kShieldDefaults;
        AutoActionSet out = ShieldApply(c, in, rules, net);
        EXPECT_EQ(out.count, 1u);
        EXPECT_TRUE(out.actions[0] == AutoAction::MemReclaim);
        EXPECT_TRUE(out.rules[0] == AutoRule::MemPressure);

        // Master-off must not change the empty-net passthrough.
        ShieldSetMaster(c, false);
        out = ShieldApply(c, in, rules, net);
        EXPECT_EQ(out.count, 1u);
        EXPECT_TRUE(out.actions[0] == AutoAction::MemReclaim);
    }

    // ----- Cmdline parse: mode + shields master -----------------
    {
        // No token -> safe defaults: Shadow mode, shields ON.
        EXPECT_TRUE(PolicyModeFromCmdline(nullptr) == PolicyMode::Shadow);
        EXPECT_TRUE(PolicyModeFromCmdline("") == PolicyMode::Shadow);
        EXPECT_TRUE(PolicyModeFromCmdline("quiet ro") == PolicyMode::Shadow);
        EXPECT_TRUE(ShieldsEnabledFromCmdline(nullptr));
        EXPECT_TRUE(ShieldsEnabledFromCmdline("quiet ro"));

        // Explicit mode tokens.
        EXPECT_TRUE(PolicyModeFromCmdline("autonomic=off") == PolicyMode::Off);
        EXPECT_TRUE(PolicyModeFromCmdline("autonomic=shadow") == PolicyMode::Shadow);
        EXPECT_TRUE(PolicyModeFromCmdline("autonomic=live") == PolicyMode::Live);
        EXPECT_TRUE(PolicyModeFromCmdline("ro autonomic=live quiet") == PolicyMode::Live);

        // Master-off token ("reel in the data" from boot).
        EXPECT_FALSE(ShieldsEnabledFromCmdline("shields=off"));
        EXPECT_TRUE(ShieldsEnabledFromCmdline("shields=on"));
        EXPECT_FALSE(ShieldsEnabledFromCmdline("ro shields=off quiet"));

        // A prefix collision must NOT match (autonomic= vs autonomicX).
        EXPECT_TRUE(PolicyModeFromCmdline("autonomicx=live") == PolicyMode::Shadow);
    }

    // ----- ShieldReconcile: live-mode net/floor reconciliation --
    // Slice 3 gives the learner real authority in Live mode. The shield
    // reconciles the net's proposal with the rule floor:
    //   - Off / Shadow      -> the rule floor actuates, net is advisory.
    //   - Live + floor veto  -> net drives, but the floor's safety actions
    //                           (e.g. SecurityEscalate) are never dropped.
    //   - Live + master-off  -> RAW net only, no floor (un-shielded data).
    //   - Live + forbidden   -> high-consequence actions stay rule-only.
    {
        auto has = [](const AutoActionSet& s, AutoAction a)
        {
            for (u32 i = 0; i < s.count; ++i)
            {
                if (s.actions[i] == a)
                {
                    return true;
                }
            }
            return false;
        };

        AutoActionSet net = {};
        net.count = 1;
        net.actions[0] = AutoAction::MemReclaim;
        net.rules[0] = AutoRule::MemPressure;

        AutoActionSet floor = {};
        floor.count = 1;
        floor.actions[0] = AutoAction::SecurityEscalate;
        floor.rules[0] = AutoRule::SecurityIntegrity;

        ShieldConfig c = kShieldDefaults;

        // Shadow: the floor actuates; the net is advisory only.
        AutoActionSet out = ShieldReconcile(c, PolicyMode::Shadow, floor, net);
        EXPECT_EQ(out.count, 1u);
        EXPECT_TRUE(has(out, AutoAction::SecurityEscalate));
        EXPECT_FALSE(has(out, AutoAction::MemReclaim));

        // Off: same — floor only.
        out = ShieldReconcile(c, PolicyMode::Off, floor, net);
        EXPECT_TRUE(has(out, AutoAction::SecurityEscalate));
        EXPECT_FALSE(has(out, AutoAction::MemReclaim));

        // Live + shields: net drives AND the floor's safety action survives.
        out = ShieldReconcile(c, PolicyMode::Live, floor, net);
        EXPECT_EQ(out.count, 2u);
        EXPECT_TRUE(has(out, AutoAction::MemReclaim));       // learner's proposal actuates
        EXPECT_TRUE(has(out, AutoAction::SecurityEscalate)); // floor not vetoed away

        // Live + master-off: RAW net only, no floor union.
        ShieldConfig raw = kShieldDefaults;
        ShieldSetMaster(raw, false);
        out = ShieldReconcile(raw, PolicyMode::Live, floor, net);
        EXPECT_EQ(out.count, 1u);
        EXPECT_TRUE(has(out, AutoAction::MemReclaim));
        EXPECT_FALSE(has(out, AutoAction::SecurityEscalate));

        // Live + forbidden_actions: a (defensive) net-proposed high-
        // consequence action is dropped; shields-off keeps it raw.
        AutoActionSet net_bad = {};
        net_bad.count = 1;
        net_bad.actions[0] = AutoAction::SecurityEscalate;
        net_bad.rules[0] = AutoRule::SecurityIntegrity;
        const AutoActionSet empty_floor = {};
        out = ShieldReconcile(c, PolicyMode::Live, empty_floor, net_bad);
        EXPECT_FALSE(has(out, AutoAction::SecurityEscalate)); // forbidden -> dropped
        out = ShieldReconcile(raw, PolicyMode::Live, empty_floor, net_bad);
        EXPECT_TRUE(has(out, AutoAction::SecurityEscalate)); // master-off -> raw
    }

    return duetos_host_test::finish_main("test_policy_shield");
}
