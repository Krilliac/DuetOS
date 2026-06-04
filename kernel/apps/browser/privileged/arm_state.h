#pragma once

#include "apps/browser/privileged/scope.h"
#include "util/types.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §13.3 / §13.10): the per-tab
 * arm state machine. A tab is Disarmed by default; arming binds a capability
 * scope; privilege never survives a navigation that leaves the privileged
 * origin (auto-disarm). Pure — boot-self-tested.
 */

namespace duetos::apps::browser::priv
{
enum class ArmState : duetos::u8
{
    Disarmed = 0,
    Armed = 1,
};

struct PrivTab
{
    ArmState state = ArmState::Disarmed;
    CapSet scope{}; // meaningful only when Armed

    void Arm(const CapSet& s)
    {
        state = ArmState::Armed;
        scope = s;
    }
    void Disarm()
    {
        state = ArmState::Disarmed;
        scope = CapSet{};
    }
    bool IsArmed() const { return state == ArmState::Armed; }

    // Called on every navigation/reload. Privilege is per-navigation: if the
    // live page no longer satisfies the privileged-origin predicate (different
    // origin/path, a redirect, or a reload to a fresh nav), auto-disarm.
    void OnNavigation(bool stillPrivilegedOrigin)
    {
        if (!stillPrivilegedOrigin)
            Disarm();
    }
};

void ArmStateSelfTest();

} // namespace duetos::apps::browser::priv
