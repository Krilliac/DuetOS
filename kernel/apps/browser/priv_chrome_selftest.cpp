#include "apps/browser.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "security/privilege/arm_state.h"
#include "security/privilege/config.h"
#include "security/privilege/scope.h"

/*
 * Privileged-Origin Mode — browser chrome + arm/disarm flow + kill switch +
 * per-navigation lifetime self-test (spec §13.5 / §13.10).
 *
 * LOGIC ONLY. The crimson armed chrome (tinted omnibox, red shield, warning
 * ribbon, red tab accent + content border) is pixel output that needs a real
 * framebuffer (VBox) to verify — out of scope for a headless boot self-test.
 * This asserts the decisions that DRIVE that chrome:
 *
 *   1. an armed tab drives the "render crimson" predicate true; disarmed false
 *   2. the Ctrl+Shift+Esc kill switch transitions Armed -> Disarmed
 *   3. OnNavigation(false) on an armed tab auto-disarms (privilege never
 *      survives leaving the privileged origin)
 *   4. when the feature is unavailable (no --allow-claude-system-access boot
 *      flag) the arm affordance predicate is false — no privileged UI at all
 *   5. the lexical privileged-origin check accepts https://claude.ai/code and
 *      rejects look-alikes (subdomain, http, wrong path)
 */

namespace duetos::apps::browser
{
namespace
{
using duetos::security::privilege::ArmState;
using duetos::security::privilege::DefaultArmScope;
using duetos::security::privilege::PrivTab;
} // namespace

void BrowserPrivChromeSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-chrome-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    // 1: pure PrivTab arm-state machine (independent of any chrome global).
    PrivTab t{};
    if (t.IsArmed())
    {
        fail(1);
        return;
    }
    t.Arm(DefaultArmScope());
    if (!t.IsArmed() || t.state != ArmState::Armed)
    {
        fail(2);
        return;
    }
    // The default scope must actually carry the §13.6 caps (non-empty).
    if (t.scope.bits == 0)
    {
        fail(3);
        return;
    }

    // 2: OnNavigation(false) on an armed tab auto-disarms; OnNavigation(true)
    // keeps it armed (the pure state machine — mirrors what StartFetch does).
    t.Arm(DefaultArmScope());
    t.OnNavigation(true);
    if (!t.IsArmed())
    {
        fail(4);
        return;
    }
    t.OnNavigation(false);
    if (t.IsArmed() || t.scope.bits != 0)
    {
        fail(5);
        return;
    }

    // 3: the LIVE chrome arm state drives BrowserPrivShouldRenderArmed().
    // Disarmed -> false; armed (via the SAME PrivArm path the reconfirm uses)
    // -> true. Restore to disarmed afterward so runtime state is untouched.
    if (BrowserPrivShouldRenderArmed())
    {
        fail(6);
        return;
    }
    priv_chrome_test::Arm();
    if (!priv_chrome_test::IsArmed() || !BrowserPrivShouldRenderArmed())
    {
        fail(7);
        return;
    }

    // 4: the kill switch (Ctrl+Shift+Esc) transitions Armed -> Disarmed.
    priv_chrome_test::KillSwitchNoReload();
    if (priv_chrome_test::IsArmed() || BrowserPrivShouldRenderArmed())
    {
        fail(8);
        return;
    }

    // 5: live OnNavigation off the privileged origin auto-disarms the global.
    priv_chrome_test::Arm();
    priv_chrome_test::OnNavigation(false);
    if (priv_chrome_test::IsArmed())
    {
        fail(9);
        return;
    }
    priv_chrome_test::Disarm(); // ensure clean runtime state regardless.

    // 6: the arm-affordance truth table. available=false => ALWAYS false
    // (feature fully off => no privileged UI), even on the privileged origin
    // / disarmed. Visible only when available && !armed && originPriv.
    if (priv_chrome_test::AffordanceVisibleFor(/*available=*/false, /*armed=*/false, /*originPriv=*/true))
    {
        fail(10);
        return;
    }
    if (priv_chrome_test::AffordanceVisibleFor(/*available=*/true, /*armed=*/true, /*originPriv=*/true))
    {
        fail(11);
        return;
    }
    if (priv_chrome_test::AffordanceVisibleFor(/*available=*/true, /*armed=*/false, /*originPriv=*/false))
    {
        fail(12);
        return;
    }
    if (!priv_chrome_test::AffordanceVisibleFor(/*available=*/true, /*armed=*/false, /*originPriv=*/true))
    {
        fail(13);
        return;
    }

    // 7: lexical privileged-origin check — accept the canonical origin + a
    // sub-path; reject http, a sibling host, a subdomain, and the wrong path.
    if (!priv_chrome_test::UrlIsPrivileged("https://claude.ai/code"))
    {
        fail(14);
        return;
    }
    if (!priv_chrome_test::UrlIsPrivileged("https://claude.ai/code/session/abc"))
    {
        fail(15);
        return;
    }
    if (priv_chrome_test::UrlIsPrivileged("http://claude.ai/code"))
    {
        fail(16);
        return;
    }
    if (priv_chrome_test::UrlIsPrivileged("https://evil.claude.ai/code"))
    {
        fail(17);
        return;
    }
    if (priv_chrome_test::UrlIsPrivileged("https://claude.ai/codex"))
    {
        fail(18);
        return;
    }
    if (priv_chrome_test::UrlIsPrivileged("https://claude.ai/"))
    {
        fail(19);
        return;
    }

    arch::SerialWrite("[priv-chrome-selftest] PASS (arm-state machine, OnNavigation auto-disarm, live armed-chrome "
                      "predicate, Ctrl+Shift+Esc kill switch, affordance truth table incl. available=false=>off, "
                      "privileged-origin lexical accept/reject)\n");
}

} // namespace duetos::apps::browser
