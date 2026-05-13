/*
 * DuetOS — kernel shell: account / authentication commands.
 *
 * Sibling TU of shell.cpp. Houses users / useradd / userdel /
 * passwd / logout / su / login. Every handler is a thin wrapper
 * around auth.h plus admin-gating inside the function body so
 * the kernel-side API stays pure data-access and is callable
 * from the login gate without capability juggling.
 */

#include "shell/shell_internal.h"

#include "core/session_restore.h"
#include "security/auth.h"
#include "security/login.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/console.h"
#include "security/attack_sim.h"
#include "security/broker.h"
#include "security/event_ring.h"
#include "security/grace.h"
#include "security/guard.h"
#include "security/policy.h"
#include "security/purple_team.h"
#include "security/rbac.h"
#include "log/klog.h"
#include "proc/process.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

const char* RoleName(AuthRole r)
{
    switch (r)
    {
    case AuthRole::Admin:
        return "admin";
    case AuthRole::User:
        return "user";
    case AuthRole::Guest:
        return "guest";
    default:
        return "?";
    }
}

AuthRole RoleFromArg(const char* s)
{
    if (StrEq(s, "admin"))
        return AuthRole::Admin;
    if (StrEq(s, "guest"))
        return AuthRole::Guest;
    return AuthRole::User;
}

} // namespace

bool RequireAdmin(const char* cmd)
{
    if (AuthIsAdmin())
    {
        return true;
    }
    // Denial = non-zero exit so scripts can react. POSIX `sudo`
    // returns 1 on auth failure; mirror that.
    ShellSetExit(1);
    ConsoleWrite("DENIED: ");
    ConsoleWrite(cmd);
    ConsoleWriteln(" REQUIRES ADMIN");
    duetos::core::Log(duetos::core::LogLevel::Warn, "shell", "admin-only command denied");
    duetos::arch::SerialWrite("[shell] denied (non-admin): ");
    duetos::arch::SerialWrite(cmd);
    duetos::arch::SerialWrite("\n");
    return false;
}

void CmdUsers()
{
    const u32 n = AuthAccountCount();
    ConsoleWrite("USERS (");
    WriteU64Dec(n);
    ConsoleWriteln(" accounts)");
    const char* active = AuthCurrentUserName();
    for (u32 i = 0; i < n; ++i)
    {
        AccountView v = {};
        if (!AuthAccountAt(i, &v))
            continue;
        ConsoleWrite("  ");
        ConsoleWrite(v.username);
        ConsoleWrite("  [");
        ConsoleWrite(RoleName(v.role));
        ConsoleWrite("]");
        if (!v.has_password)
        {
            ConsoleWrite("  (no password)");
        }
        if (v.locked)
        {
            ConsoleWrite("  LOCKED");
        }
        if (v.failed_attempts > 0)
        {
            ConsoleWrite("  fails=");
            WriteU64Dec(v.failed_attempts);
        }
        ConsoleWrite("  logins=");
        WriteU64Dec(v.total_logins);
        if (active[0] != '\0' && StrEq(active, v.username))
        {
            ConsoleWrite("  *");
        }
        ConsoleWriteChar('\n');
    }
}

void CmdUnlock(u32 argc, char** argv)
{
    if (!AuthIsAdmin())
    {
        ConsoleWriteln("UNLOCK: PERMISSION DENIED (ADMIN ONLY)");
        return;
    }
    if (argc < 2)
    {
        ConsoleWriteln("UNLOCK: USAGE: UNLOCK <NAME>");
        return;
    }
    if (!AuthUnlockUser(argv[1]))
    {
        ConsoleWriteln("UNLOCK: FAILED (UNKNOWN USER)");
        return;
    }
    ConsoleWrite("UNLOCK: CLEARED LOCKOUT FOR ");
    ConsoleWriteln(argv[1]);
}

void CmdUseradd(u32 argc, char** argv)
{
    if (!AuthIsAdmin())
    {
        ConsoleWriteln("USERADD: PERMISSION DENIED (ADMIN ONLY)");
        return;
    }
    if (argc < 3)
    {
        ConsoleWriteln("USERADD: USAGE: USERADD <NAME> <PASSWORD> [ROLE]");
        ConsoleWriteln("  ROLE: admin | user (default) | guest");
        return;
    }
    const AuthRole role = (argc >= 4) ? RoleFromArg(argv[3]) : AuthRole::User;
    if (!AuthAddUser(argv[1], argv[2], role))
    {
        ConsoleWriteln("USERADD: FAILED (DUPLICATE, FULL TABLE, OR INVALID NAME/PASSWORD)");
        return;
    }
    ConsoleWrite("USERADD: CREATED ");
    ConsoleWrite(argv[1]);
    ConsoleWrite(" [");
    ConsoleWrite(RoleName(role));
    ConsoleWriteln("]");
}

void CmdUserdel(u32 argc, char** argv)
{
    if (!AuthIsAdmin())
    {
        ConsoleWriteln("USERDEL: PERMISSION DENIED (ADMIN ONLY)");
        return;
    }
    if (argc < 2)
    {
        ConsoleWriteln("USERDEL: USAGE: USERDEL <NAME>");
        return;
    }
    if (!AuthDeleteUser(argv[1]))
    {
        ConsoleWriteln("USERDEL: FAILED (UNKNOWN USER OR LAST ADMIN)");
        return;
    }
    ConsoleWrite("USERDEL: REMOVED ");
    ConsoleWriteln(argv[1]);
}

void CmdPasswd(u32 argc, char** argv)
{
    // Self-service flow: `passwd <old> <new>` — change the
    // current user's password. Admin flow: `passwd <name>
    // <new> --force` — force-set another user's password.
    const char* me = AuthCurrentUserName();
    if (me[0] == '\0')
    {
        ConsoleWriteln("PASSWD: NO ACTIVE SESSION");
        return;
    }
    if (argc == 3)
    {
        if (!AuthChangePassword(me, argv[1], argv[2]))
        {
            ConsoleWriteln("PASSWD: FAILED (WRONG OLD PASSWORD OR INVALID NEW PASSWORD)");
            return;
        }
        ConsoleWriteln("PASSWD: PASSWORD UPDATED");
        return;
    }
    if (argc == 4)
    {
        if (!AuthIsAdmin())
        {
            ConsoleWriteln("PASSWD: PERMISSION DENIED (ADMIN ONLY FOR FORCE RESET)");
            return;
        }
        if (!StrEq(argv[3], "--force"))
        {
            ConsoleWriteln("PASSWD: USAGE: PASSWD <USER> <NEW_PW> --force");
            return;
        }
        if (!AuthChangePassword(argv[1], nullptr, argv[2]))
        {
            ConsoleWriteln("PASSWD: FAILED (UNKNOWN USER OR INVALID PASSWORD)");
            return;
        }
        ConsoleWrite("PASSWD: PASSWORD FOR ");
        ConsoleWrite(argv[1]);
        ConsoleWriteln(" UPDATED");
        return;
    }
    ConsoleWriteln("PASSWD: USAGE:");
    ConsoleWriteln("  PASSWD <OLD_PW> <NEW_PW>                (SELF-SERVICE)");
    ConsoleWriteln("  PASSWD <USER> <NEW_PW> --force          (ADMIN RESET)");
}

void CmdLogout()
{
    if (!AuthIsAuthenticated())
    {
        ConsoleWriteln("LOGOUT: NO ACTIVE SESSION");
        return;
    }
    ConsoleWrite("LOGOUT: GOODBYE, ");
    ConsoleWriteln(AuthCurrentUserName());
    // Snapshot theme + window positions before the gate goes
    // back up — the next login should land in the same desktop
    // layout the user just left.
    duetos::core::SessionRestoreSave();
    LoginReopen();
}

void CmdSu(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("SU: USAGE: SU <USER> <PASSWORD>");
        return;
    }
    if (!AuthLogin(argv[1], argv[2]))
    {
        ConsoleWriteln("SU: AUTHENTICATION FAILED");
        return;
    }
    ConsoleWrite("SU: SWITCHED TO ");
    ConsoleWriteln(argv[1]);
}

void CmdLoginCmd(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("LOGIN: USAGE: LOGIN <USER> <PASSWORD>");
        return;
    }
    if (!AuthLogin(argv[1], argv[2]))
    {
        ConsoleWriteln("LOGIN: AUTHENTICATION FAILED");
        return;
    }
    ConsoleWrite("LOGIN: WELCOME, ");
    ConsoleWriteln(argv[1]);
}

void CmdIdleLock(u32 argc, char** argv)
{
    using duetos::core::IdleLockSetThresholdSeconds;
    using duetos::core::IdleLockThresholdSeconds;
    using duetos::core::InputLastActivityTicks;

    if (argc < 2 || StrEq(argv[1], "show") || StrEq(argv[1], "status"))
    {
        const u32 secs = IdleLockThresholdSeconds();
        ConsoleWrite("IDLELOCK: threshold=");
        WriteU64Dec(secs);
        ConsoleWrite(" sec");
        if (secs == 0)
        {
            ConsoleWrite(" (DISABLED)");
        }
        ConsoleWriteln("");
        ConsoleWrite("IDLELOCK: last_activity_tick=");
        WriteU64Dec(InputLastActivityTicks());
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "off") || StrEq(argv[1], "disable"))
    {
        if (!RequireAdmin("IDLELOCK SET"))
            return;
        IdleLockSetThresholdSeconds(0);
        ConsoleWriteln("IDLELOCK: disabled");
        return;
    }
    if (StrEq(argv[1], "set") && argc >= 3)
    {
        if (!RequireAdmin("IDLELOCK SET"))
            return;
        const i64 secs = ParseInt(argv[2]);
        if (secs < 0 || secs > 86400)
        {
            ConsoleWriteln("IDLELOCK: seconds out of range (0..86400; 0 disables)");
            return;
        }
        IdleLockSetThresholdSeconds(static_cast<u32>(secs));
        ConsoleWrite("IDLELOCK: threshold set to ");
        WriteU64Dec(secs);
        ConsoleWriteln(" sec");
        return;
    }
    ConsoleWriteln("IDLELOCK: usage: idlelock <show|set <seconds>|off>");
}

void CmdGuard(u32 argc, char** argv)
{
    // Show / control the security guard.
    //   guard                  status line
    //   guard on | advisory    switch to advisory mode
    //   guard enforce          switch to enforce mode (prompts on Warn/Deny)
    //   guard off              disable the guard entirely (use sparingly)
    //   guard test             re-run GuardSelfTest
    namespace sec = duetos::security;
    if (argc < 2)
    {
        ConsoleWrite("GUARD MODE   : ");
        ConsoleWriteln(sec::GuardModeName(sec::GuardMode()));
        ConsoleWrite("SCANS  : ");
        WriteU64Hex(sec::GuardScanCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("ALLOW  : ");
        WriteU64Hex(sec::GuardAllowCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("WARN   : ");
        WriteU64Hex(sec::GuardWarnCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("DENY   : ");
        WriteU64Hex(sec::GuardDenyCount(), 0);
        ConsoleWriteln("");
        const sec::Report* last = sec::GuardLastReport();
        if (last != nullptr && last->finding_count > 0)
        {
            ConsoleWrite("LAST REPORT FINDINGS: ");
            WriteU64Hex(last->finding_count, 0);
            ConsoleWriteln("");
        }
        ConsoleWriteln("USAGE: GUARD [ON|ADVISORY|ENFORCE|OFF|TEST]");
        return;
    }
    // Mutating subcommands change the kernel's security posture
    // and must be admin-gated so a passwordless guest can't flip
    // the guard to Off and disable image-load protection. Status
    // read above is harmless (just counters).
    if (StrEq(argv[1], "on") || StrEq(argv[1], "advisory"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Advisory);
        ConsoleWriteln("GUARD: ADVISORY (logs, never blocks)");
        return;
    }
    if (StrEq(argv[1], "enforce"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Enforce);
        ConsoleWriteln("GUARD: ENFORCE (prompts on Warn/Deny, default-deny on timeout)");
        return;
    }
    if (StrEq(argv[1], "off"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Off);
        ConsoleWriteln("GUARD: OFF (all images pass through)");
        return;
    }
    if (StrEq(argv[1], "test"))
    {
        if (!RequireAdmin("GUARD TEST"))
            return;
        sec::GuardSelfTest();
        ConsoleWriteln("(self-test output on COM1)");
        return;
    }
    ConsoleWriteln("GUARD: UNKNOWN SUBCOMMAND");
}

void CmdAttackSim()
{
    duetos::security::AttackSimRun();
    const auto& s = duetos::security::AttackSimSummary();
    ConsoleWrite("ATTACK SIM COMPLETE: ");
    WriteU64Dec(s.passed);
    ConsoleWrite(" passed, ");
    WriteU64Dec(s.failed);
    ConsoleWrite(" failed, ");
    WriteU64Dec(s.skipped);
    ConsoleWriteln(" skipped");
    for (u64 i = 0; i < s.count; ++i)
    {
        ConsoleWrite("  [");
        ConsoleWrite(duetos::security::AttackOutcomeName(s.results[i].outcome));
        ConsoleWrite("] ");
        ConsoleWrite(s.results[i].name);
        ConsoleWrite(" -> ");
        ConsoleWriteln(s.results[i].detector);
    }
}

void CmdSecEvents(u32 argc, char** argv)
{
    namespace sec = duetos::security;
    u64 n = 32;
    if (argc >= 2)
    {
        // Parse a small unsigned decimal. Bad input falls back to default.
        u64 parsed = 0;
        bool any = false;
        for (const char* p = argv[1]; *p != '\0'; ++p)
        {
            if (*p < '0' || *p > '9')
            {
                any = false;
                break;
            }
            parsed = parsed * 10 + static_cast<u64>(*p - '0');
            any = true;
        }
        if (any)
            n = parsed;
    }
    const auto stats = sec::EventRingStatsRead();
    ConsoleWrite("SECEVENTS: published=");
    WriteU64Dec(stats.published_total);
    ConsoleWrite(" dropped_oldest=");
    WriteU64Dec(stats.dropped_oldest);
    ConsoleWrite(" capacity=");
    WriteU64Dec(stats.capacity);
    ConsoleWriteln("");
    ConsoleWriteln("(detailed event lines on COM1)");
    sec::EventRingDumpRecent(n);
}

void CmdPolicy(u32 argc, char** argv)
{
    namespace sec = duetos::security;
    if (argc < 2 || StrEq(argv[1], "show"))
    {
        const auto snap = sec::PolicyCurrent();
        ConsoleWrite("POLICY PROFILE : ");
        ConsoleWriteln(sec::PolicyProfileName(snap.profile));
        ConsoleWrite("GUARD          : ");
        ConsoleWriteln(sec::GuardModeName(snap.guard_mode));
        ConsoleWrite("PERSISTENCE    : ");
        ConsoleWriteln(snap.persistence_mode == sec::PersistenceMode::Deny ? "DENY" : "ADVISORY");
        ConsoleWrite("BLOCKGUARD     : ");
        ConsoleWriteln(snap.write_guard_mode == duetos::drivers::storage::WriteGuardMode::Deny       ? "DENY"
                       : snap.write_guard_mode == duetos::drivers::storage::WriteGuardMode::Advisory ? "ADVISORY"
                                                                                                     : "OFF");
        ConsoleWriteln("USAGE: POLICY [SHOW|SET <PROFILE>|DIFF <PROFILE>]");
        return;
    }
    if (StrEq(argv[1], "set") && argc >= 3)
    {
        if (!RequireAdmin("POLICY SET"))
            return;
        sec::PolicyProfile p = sec::PolicyProfile::Default;
        if (StrEq(argv[2], "default") || StrEq(argv[2], "DEFAULT"))
            p = sec::PolicyProfile::Default;
        else if (StrEq(argv[2], "lab") || StrEq(argv[2], "LAB"))
            p = sec::PolicyProfile::Lab;
        else if (StrEq(argv[2], "production") || StrEq(argv[2], "PRODUCTION") || StrEq(argv[2], "prod"))
            p = sec::PolicyProfile::Production;
        else if (StrEq(argv[2], "forensic") || StrEq(argv[2], "FORENSIC"))
            p = sec::PolicyProfile::Forensic;
        else
        {
            ConsoleWriteln("POLICY: UNKNOWN PROFILE (use default|lab|production|forensic)");
            return;
        }
        sec::PolicySet(p, 0);
        ConsoleWrite("POLICY SET TO ");
        ConsoleWriteln(sec::PolicyProfileName(p));
        return;
    }
    if (StrEq(argv[1], "diff") && argc >= 3)
    {
        ConsoleWriteln("(policy diff: see COM1 — not yet wired into console)");
        return;
    }
    ConsoleWriteln("POLICY: UNKNOWN SUBCOMMAND");
}

// ---------------------------------------------------------------
// RBAC + elevation broker surface.
//
// `elevate <cap>`   — prompt for the current user's password and,
//                     on success, add the cap to the kernel shell's
//                     pseudo-process. Future shell commands that
//                     consult `g_shell_proc.caps` honour the grant
//                     for the configured grace window.
// `elevate off`     — clear every cap held by the pseudo-process
//                     and drop the broker grants from the cache.
// `roles [me]`      — list every registered role (or, with `me`,
//                     the roles the active session belongs to).
// `elevations`      — dump the live grace-cache rows so the
//                     operator can see what is currently elevated
//                     and how long is left.
//
// The pseudo-process is a `core::Process` with a sentinel pid; the
// broker writes its caps and the grace cache keys against that pid
// the same way it would for a real ring-3 process.
// ---------------------------------------------------------------
namespace
{

constexpr u64 kShellPseudoPid = ~0ull;
duetos::core::Process g_shell_proc{};
bool g_shell_proc_initialized = false;

void EnsureShellProcInitialized()
{
    if (g_shell_proc_initialized)
        return;
    g_shell_proc.pid = kShellPseudoPid;
    g_shell_proc.caps = duetos::core::CapSetEmpty();
    g_shell_proc_initialized = true;
}

duetos::core::Cap ParseCapArg(const char* s)
{
    if (s == nullptr || s[0] == '\0')
        return duetos::core::kCapNone;
    // Accept both "FsWrite" and "kCapFsWrite" forms.
    for (u32 c = 1; c < static_cast<u32>(duetos::core::kCapCount); ++c)
    {
        const char* name = duetos::core::CapName(static_cast<duetos::core::Cap>(c));
        if (name == nullptr)
            continue;
        if (StrEq(s, name))
            return static_cast<duetos::core::Cap>(c);
        // Tolerate the "kCap" prefix being omitted.
        if (name[0] == 'k' && name[1] == 'C' && name[2] == 'a' && name[3] == 'p')
        {
            if (StrEq(s, name + 4))
                return static_cast<duetos::core::Cap>(c);
        }
    }
    return duetos::core::kCapNone;
}

void PrintCapBundle(u64 mask)
{
    bool first = true;
    for (u32 c = 1; c < static_cast<u32>(duetos::core::kCapCount); ++c)
    {
        if ((mask & (1ULL << c)) == 0)
            continue;
        if (!first)
            ConsoleWrite(", ");
        ConsoleWrite(duetos::core::CapName(static_cast<duetos::core::Cap>(c)));
        first = false;
    }
    if (first)
        ConsoleWrite("(empty)");
}

} // namespace

bool ShellIsElevatedNow()
{
    EnsureShellProcInitialized();
    // A cap held by the pseudo-process whose grace row has expired
    // should be considered dropped. Sweep the cache, then trim caps
    // whose grant is no longer cached. v0 keeps the cap bits in
    // sync with the cache by rechecking on every call.
    duetos::security::GraceCacheReap();
    for (u32 c = 1; c < static_cast<u32>(duetos::core::kCapCount); ++c)
    {
        const duetos::core::Cap cap = static_cast<duetos::core::Cap>(c);
        if ((g_shell_proc.caps.bits & (1ULL << c)) == 0)
            continue;
        if (!duetos::security::GraceCacheLookup(kShellPseudoPid, cap))
            g_shell_proc.caps.bits &= ~(1ULL << c);
    }
    return g_shell_proc.caps.bits != 0;
}

void CmdElevate(u32 argc, char** argv)
{
    EnsureShellProcInitialized();
    if (argc < 2)
    {
        ConsoleWriteln("ELEVATE: USAGE:");
        ConsoleWriteln("  ELEVATE <CAP>        prompt + grant cap for grace window");
        ConsoleWriteln("  ELEVATE OFF          drop every active elevation");
        ConsoleWriteln("  (CAP example: FsWrite, NetAdmin, Debug — see ROLES)");
        return;
    }
    if (StrEq(argv[1], "off") || StrEq(argv[1], "OFF"))
    {
        duetos::security::GraceCacheExpirePid(kShellPseudoPid);
        g_shell_proc.caps = duetos::core::CapSetEmpty();
        ConsoleWriteln("ELEVATE: cleared shell elevation state");
        return;
    }
    const duetos::core::Cap cap = ParseCapArg(argv[1]);
    if (cap == duetos::core::kCapNone)
    {
        ConsoleWrite("ELEVATE: UNKNOWN CAP '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("' — run ROLES to see available caps");
        return;
    }
    duetos::security::BrokerRequest req{};
    req.proc = &g_shell_proc;
    req.cap = cap;
    req.reason = argv[1];
    const auto outcome = duetos::security::BrokerRequestElevation(req);
    ConsoleWrite("ELEVATE: ");
    ConsoleWrite(duetos::security::BrokerOutcomeName(outcome));
    if (outcome == duetos::security::BrokerOutcome::Granted)
    {
        ConsoleWrite(" — cap ");
        ConsoleWrite(duetos::core::CapName(cap));
        ConsoleWriteln(" held for grace window");
    }
    else
    {
        ConsoleWriteln("");
    }
}

void CmdRoles(u32 argc, char** argv)
{
    if (argc >= 2 && (StrEq(argv[1], "me") || StrEq(argv[1], "ME")))
    {
        const char* who = AuthCurrentUserName();
        ConsoleWrite("ROLES FOR ");
        ConsoleWrite((who != nullptr && who[0] != '\0') ? who : "(no session)");
        ConsoleWriteln(":");
        const u32 mask = duetos::security::RbacAccountRoleMask(who);
        if (mask == 0)
        {
            ConsoleWriteln("  (none — no roles attached, broker will deny every request)");
            return;
        }
        const u32 n = duetos::security::RbacRoleCount();
        for (u32 i = 0; i < n; ++i)
        {
            duetos::security::Role r{};
            if (!duetos::security::RbacRoleAt(i, &r))
                continue;
            const duetos::security::RoleId id = duetos::security::RbacFindRole(r.name);
            if ((mask & (1u << id)) == 0)
                continue;
            ConsoleWrite("  ");
            ConsoleWrite(r.name);
            ConsoleWrite(" -> ");
            PrintCapBundle(r.policy.cap_mask);
            ConsoleWriteln("");
        }
        return;
    }
    const u32 n = duetos::security::RbacRoleCount();
    ConsoleWrite("ROLES (");
    WriteU64Dec(n);
    ConsoleWriteln("):");
    for (u32 i = 0; i < n; ++i)
    {
        duetos::security::Role r{};
        if (!duetos::security::RbacRoleAt(i, &r))
            continue;
        ConsoleWrite("  ");
        ConsoleWrite(r.name);
        ConsoleWrite("  caps: ");
        PrintCapBundle(r.policy.cap_mask);
        ConsoleWriteln("");
    }
}

void CmdElevations()
{
    duetos::security::GraceCacheReap();
    const u32 n = duetos::security::GraceCacheLiveCount();
    ConsoleWrite("ELEVATIONS LIVE: ");
    WriteU64Dec(n);
    ConsoleWriteln("");
    for (u32 i = 0; i < n; ++i)
    {
        duetos::security::GraceEntry e{};
        if (!duetos::security::GraceCacheEntryAt(i, &e))
            continue;
        ConsoleWrite("  pid=");
        WriteU64Hex(e.pid, 0);
        ConsoleWrite("  cap=");
        ConsoleWrite(duetos::core::CapName(e.cap));
        ConsoleWrite("  expires_ns=");
        WriteU64Hex(e.deadline_ns, 0);
        ConsoleWriteln("");
    }
}

void CmdPurple()
{
    if (!RequireAdmin("PURPLE"))
        return;
    const auto s = duetos::security::PurpleTeamRunAll();
    ConsoleWrite("PURPLE: attacks=");
    WriteU64Dec(s.attacks_run);
    ConsoleWrite(" passed=");
    WriteU64Dec(s.attacks_passed);
    ConsoleWrite(" coverage=");
    WriteU64Dec(s.coverage_pct);
    ConsoleWriteln("%");
    ConsoleWrite("PURPLE: events_observed=");
    WriteU64Dec(s.events_observed);
    ConsoleWrite(" runbooks=");
    WriteU64Dec(s.runbooks_emitted);
    ConsoleWriteln("");
}

} // namespace duetos::core::shell::internal
