/*
 * DuetOS — elevation broker, v0.
 *
 * See broker.h for the public contract and design rationale.
 *
 * Note on Argon2id: the v0 broker uses whatever KDF the existing
 * `AuthVerify` runs (PBKDF2-HMAC-SHA256). Argon2id is a follow-up
 * tracked in wiki/security/RBAC-and-Elevation.md and the Roadmap.
 *
 * Note on Win32 facade: NtAdjustPrivilegesToken routing to this
 * broker is a follow-up tracked in the same wiki page. The v0
 * Win32 surface is pure-facade per the existing isolation rule.
 */

#include "security/broker.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/console.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "security/auth.h"
#include "security/event_ring.h"
#include "security/grace.h"
#include "security/rbac.h"
#include "util/types.h"

namespace duetos::security
{

using duetos::core::AuthCurrentUserName;
using duetos::core::AuthIsAuthenticated;
using duetos::core::AuthVerify;
using duetos::core::Panic;
using duetos::core::Cap;
using duetos::core::CapName;
using duetos::core::CapSet;
using duetos::core::CapSetHas;
using duetos::core::kCapCount;
using duetos::core::kCapNone;
using duetos::core::Process;

namespace
{

BrokerPromptHook g_prompt_hook = nullptr;

constexpr u32 kPwBufSize = 64;

bool DefaultPromptCli(const char* reason, char* out_pw, u32 out_pw_cap)
{
    using namespace duetos::drivers::video;
    ConsoleWrite("[elevate] password required for ");
    ConsoleWrite(reason != nullptr ? reason : "(unknown)");
    ConsoleWrite(" (esc to cancel): ");

    u32 pos = 0;
    for (;;)
    {
        const auto ev = duetos::drivers::input::Ps2KeyboardReadEvent();
        if (ev.is_release)
            continue;
        if (ev.code == duetos::drivers::input::kKeyEsc)
        {
            ConsoleWrite("\n[elevate] cancelled\n");
            return false;
        }
        if (ev.code == duetos::drivers::input::kKeyEnter)
        {
            ConsoleWrite("\n");
            if (pos < out_pw_cap)
                out_pw[pos] = '\0';
            else
                out_pw[out_pw_cap - 1] = '\0';
            return true;
        }
        if (ev.code == duetos::drivers::input::kKeyBackspace)
        {
            if (pos > 0)
                --pos;
            continue;
        }
        if (ev.code >= 0x20 && ev.code <= 0x7E && pos + 1 < out_pw_cap)
        {
            out_pw[pos++] = static_cast<char>(ev.code);
            // Echo a single mask char so the user sees they typed.
            ConsoleWrite("*");
        }
    }
}

bool DefaultPromptGui(const char* reason, char* out_pw, u32 out_pw_cap)
{
    using namespace duetos::drivers::video;

    // Centered modal panel — same draw discipline as the boot login.
    // Lives above the desktop but below the cursor; the compositor's
    // existing repaint flow renders other windows normally on either
    // side of each keypress (we re-take the lock per repaint).

    const auto fb = FramebufferGet();
    const u32 panel_w = 380;
    const u32 panel_h = 130;
    const u32 px = (fb.width > panel_w) ? (fb.width - panel_w) / 2 : 0;
    const u32 py = (fb.height > panel_h) ? (fb.height - panel_h) / 2 : 0;

    constexpr u32 kPanelBg = 0x00181820;
    constexpr u32 kPanelBorder = 0x00808090;
    constexpr u32 kTitleBg = 0x00282838;
    constexpr u32 kFieldBg = 0x00101018;
    constexpr u32 kText = 0x00E0E0E8;
    constexpr u32 kAccent = 0x0070C0FF;

    auto Repaint = [&](const char* mask_text)
    {
        CompositorLock();
        FramebufferFillRect(px, py, panel_w, panel_h, kPanelBg);
        FramebufferFillRect(px, py, panel_w, 1, kPanelBorder);
        FramebufferFillRect(px, py + panel_h - 1, panel_w, 1, kPanelBorder);
        FramebufferFillRect(px, py, 1, panel_h, kPanelBorder);
        FramebufferFillRect(px + panel_w - 1, py, 1, panel_h, kPanelBorder);
        FramebufferFillRect(px + 1, py + 1, panel_w - 2, 18, kTitleBg);
        FramebufferDrawString(px + 8, py + 4, "ELEVATE PRIVILEGES", kAccent, kTitleBg);
        FramebufferDrawString(px + 12, py + 32, "PASSWORD FOR:", kText, kPanelBg);
        FramebufferDrawString(px + 12, py + 44, reason != nullptr ? reason : "(unknown)", kAccent, kPanelBg);
        FramebufferFillRect(px + 12, py + 70, panel_w - 24, 20, kFieldBg);
        FramebufferDrawString(px + 16, py + 75, mask_text, kText, kFieldBg);
        FramebufferDrawString(px + 12, py + 100, "[ENTER] OK    [ESC] CANCEL", kText, kPanelBg);
        CompositorUnlock();
    };

    char mask[kPwBufSize] = {};
    Repaint(mask);

    u32 pos = 0;
    for (;;)
    {
        const auto ev = duetos::drivers::input::Ps2KeyboardReadEvent();
        if (ev.is_release)
            continue;
        if (ev.code == duetos::drivers::input::kKeyEsc)
        {
            // Repaint without modal — desktop compose runs on next
            // input-loop iteration in main.cpp; force a no-op repaint
            // by drawing the panel area back as transparent isn't
            // safe (we'd race the compositor). Easier: leave the
            // panel; the next compositor recompose triggered by the
            // kbd reader's normal flow will clear it. v0 accepts
            // the brief flash.
            return false;
        }
        if (ev.code == duetos::drivers::input::kKeyEnter)
        {
            if (pos < out_pw_cap)
                out_pw[pos] = '\0';
            else
                out_pw[out_pw_cap - 1] = '\0';
            return true;
        }
        if (ev.code == duetos::drivers::input::kKeyBackspace)
        {
            if (pos > 0)
            {
                --pos;
                mask[pos] = '\0';
                Repaint(mask);
            }
            continue;
        }
        if (ev.code >= 0x20 && ev.code <= 0x7E && pos + 1 < out_pw_cap)
        {
            out_pw[pos++] = static_cast<char>(ev.code);
            if (pos < kPwBufSize)
            {
                mask[pos - 1] = '*';
                mask[pos] = '\0';
            }
            Repaint(mask);
        }
    }
}

bool RunPrompt(const char* reason, char* out_pw, u32 cap)
{
    if (g_prompt_hook != nullptr)
        return g_prompt_hook(reason, out_pw, cap);
    // v0: pick TTY vs GUI based on the active display mode.
    if (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty)
        return DefaultPromptCli(reason, out_pw, cap);
    return DefaultPromptGui(reason, out_pw, cap);
}

void ZeroBuf(char* buf, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        buf[i] = 0;
}

} // namespace

void BrokerSetPromptHook(BrokerPromptHook hook)
{
    g_prompt_hook = hook;
}

const char* BrokerOutcomeName(BrokerOutcome o)
{
    switch (o)
    {
    case BrokerOutcome::Granted:
        return "Granted";
    case BrokerOutcome::Denied:
        return "Denied";
    case BrokerOutcome::BadPassword:
        return "BadPassword";
    case BrokerOutcome::Cancelled:
        return "Cancelled";
    case BrokerOutcome::NotInteractive:
        return "NotInteractive";
    case BrokerOutcome::NoSession:
        return "NoSession";
    case BrokerOutcome::InvalidCap:
        return "InvalidCap";
    }
    return "?";
}

BrokerOutcome BrokerRequestElevation(const BrokerRequest& req)
{
    if (req.cap == kCapNone || req.cap >= kCapCount)
        return BrokerOutcome::InvalidCap;
    if (req.proc == nullptr)
        return BrokerOutcome::InvalidCap;
    if (!AuthIsAuthenticated())
        return BrokerOutcome::NoSession;

    // Fast path: cache hit.
    const u64 pid = req.proc->pid;
    if (GraceCacheLookup(pid, req.cap))
    {
        req.proc->caps.bits |= (1ULL << static_cast<u32>(req.cap));
        return BrokerOutcome::Granted;
    }

    // Role gate. The signed-in user's roles decide whether this cap
    // is even reachable — a typed password against a role-less
    // account does NOT grant.
    const char* user = AuthCurrentUserName();
    RoleId role = kRbacRoleInvalid;
    u32 grace = kRbacDefaultGraceSeconds;
    if (!RbacResolveElevation(user, req.cap, &role, &grace))
    {
        KLOG_WARN("broker", "elevation denied: role gate refused");
        return BrokerOutcome::Denied;
    }

    // Prompt — up to kBrokerMaxAttempts tries before giving up.
    char pw[kPwBufSize] = {};
    for (u32 attempt = 0; attempt < kBrokerMaxAttempts; ++attempt)
    {
        ZeroBuf(pw, sizeof(pw));
        const bool got = RunPrompt(req.reason != nullptr ? req.reason : CapName(req.cap), pw, sizeof(pw));
        if (!got)
        {
            ZeroBuf(pw, sizeof(pw));
            return BrokerOutcome::Cancelled;
        }
        if (AuthVerify(user, pw))
        {
            ZeroBuf(pw, sizeof(pw));
            // Cache the grant unless the role policy says no_cache.
            if (grace > 0)
                GraceCacheInsert(pid, req.cap, grace);
            req.proc->caps.bits |= (1ULL << static_cast<u32>(req.cap));
            KLOG_WARN("broker", "elevation granted");
            return BrokerOutcome::Granted;
        }
        KLOG_WARN("broker", "elevation: bad password");
    }
    ZeroBuf(pw, sizeof(pw));
    return BrokerOutcome::BadPassword;
}

namespace
{

// Self-test hook: a prompt hook that returns a hard-coded password
// (whatever the seeded admin account uses, "admin"). Lets the
// self-test exercise the cache + role gate + verify glue without
// any actual keyboard input.
bool SelfTestPromptOk(const char* /*reason*/, char* out_pw, u32 cap)
{
    const char* p = "admin";
    u32 i = 0;
    for (; p[i] != '\0' && i + 1 < cap; ++i)
        out_pw[i] = p[i];
    out_pw[i] = '\0';
    return true;
}

bool SelfTestPromptBad(const char* /*reason*/, char* out_pw, u32 cap)
{
    const char* p = "wrongpw";
    u32 i = 0;
    for (; p[i] != '\0' && i + 1 < cap; ++i)
        out_pw[i] = p[i];
    out_pw[i] = '\0';
    return true;
}

} // namespace

void BrokerSelfTest()
{
    arch::SerialWrite("[broker] self-test: role gate + verify + cache glue\n");

    // Construct a synthetic process. The broker only touches `pid`
    // and `caps`, so a stack-allocated Process is fine.
    static Process synth{};
    synth.pid = 0x4E1E4A7E;
    synth.caps = duetos::core::CapSetEmpty();

    // Self-test relies on the seeded admin account (auth.cpp init).
    // The broker is called BEFORE LoginStart in the boot order, so
    // no session is yet active — temporarily log admin in for the
    // duration of the test, then log out.
    const bool had_session = AuthIsAuthenticated();
    if (!had_session)
    {
        if (!duetos::core::AuthLogin("admin", "admin"))
            Panic("broker", "self-test: admin/admin verify failed");
    }

    BrokerSetPromptHook(SelfTestPromptOk);
    BrokerRequest req{};
    req.proc = &synth;
    req.cap = duetos::core::kCapFsWrite;
    req.reason = "FILE WRITE (selftest)";
    BrokerOutcome o1 = BrokerRequestElevation(req);
    if (o1 != BrokerOutcome::Granted)
        Panic("broker", "self-test: first request not granted");
    if (!CapSetHas(synth.caps, duetos::core::kCapFsWrite))
        Panic("broker", "self-test: granted but cap bit not set");

    // Second call should hit the cache (no prompt). Replace the
    // hook with the bad-password one — if the cache works the
    // prompt is never invoked, so the bad password doesn't matter.
    BrokerSetPromptHook(SelfTestPromptBad);
    BrokerOutcome o2 = BrokerRequestElevation(req);
    if (o2 != BrokerOutcome::Granted)
        Panic("broker", "self-test: cached request not granted");

    // Drop the cache entry; the next call should reprompt and fail.
    GraceCacheExpirePid(synth.pid);
    synth.caps.bits &= ~(1ULL << static_cast<u32>(duetos::core::kCapFsWrite));
    BrokerOutcome o3 = BrokerRequestElevation(req);
    if (o3 != BrokerOutcome::BadPassword)
        Panic("broker", "self-test: bad-password did not BadPassword");
    if (CapSetHas(synth.caps, duetos::core::kCapFsWrite))
        Panic("broker", "self-test: bad password granted a cap");

    BrokerSetPromptHook(nullptr);

    if (!had_session)
        duetos::core::AuthLogout();

    arch::SerialWrite("[broker] self-test: PASS\n");
}

} // namespace duetos::security
