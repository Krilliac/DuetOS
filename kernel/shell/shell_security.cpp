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

#include "security/auth.h"
#include "security/login.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/console.h"
#include "security/attack_sim.h"
#include "security/guard.h"
#include "log/klog.h"

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
    }
    return "?";
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
        if (active[0] != '\0' && StrEq(active, v.username))
        {
            ConsoleWrite("  *");
        }
        ConsoleWriteChar('\n');
    }
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

} // namespace duetos::core::shell::internal
