#include "apps/browser/privileged/arm_state.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser::priv
{
void ArmStateSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-arm-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    PrivTab t;

    // 1: a fresh tab is Disarmed.
    if (t.IsArmed() || t.state != ArmState::Disarmed)
    {
        fail(1);
        return;
    }
    // 2: arming binds the default scope (and ONLY the five caps — bits 0x1F;
    //    there is no installHandler bit to leak).
    t.Arm(DefaultArmScope());
    if (!t.IsArmed() || !t.scope.Has(Cap::FsWrite) || !t.scope.Has(Cap::Net) || t.scope.bits != 0x1Fu)
    {
        fail(2);
        return;
    }
    // 3: OnNavigation(true) — still on the privileged origin — stays armed.
    t.OnNavigation(true);
    if (!t.IsArmed())
    {
        fail(3);
        return;
    }
    // 4: OnNavigation(false) — left the privileged origin — auto-disarms.
    t.OnNavigation(false);
    if (t.IsArmed() || t.scope.bits != 0)
    {
        fail(4);
        return;
    }
    // 5: explicit Disarm clears arm + scope.
    t.Arm(DefaultArmScope());
    t.Disarm();
    if (t.IsArmed() || t.scope.Has(Cap::FsRead) || t.scope.bits != 0)
    {
        fail(5);
        return;
    }

    arch::SerialWrite("[priv-arm-selftest] PASS (fresh=disarmed, arm binds 5-cap scope, nav-stay/nav-auto-disarm, "
                      "explicit disarm clears)\n");
}

} // namespace duetos::apps::browser::priv
