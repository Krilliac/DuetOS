#include "drivers/video/console.h"
#include "net/drsh/drsh.h"
#include "shell/shell_internal.h"
#include "util/types.h"

/*
 * Shell command — `drshd` (DRSH remote-access service).
 *
 * Sub-verbs:
 *   drshd status              — show service state, counters, port
 *   drshd start [port]        — bring up listener (admin-gated)
 *   drshd stop                — tear down listener (admin-gated)
 *   drshd passwd <password>   — set / replace the pre-shared key
 *                                (admin-gated; cleared by passing "")
 *
 * The service is OFF by default after boot. Admin must explicitly
 * set a password and then start the listener.
 */

namespace duetos::core::shell::internal
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteln;
using duetos::net::drsh::DrshServerStart;
using duetos::net::drsh::DrshServerStatus;
using duetos::net::drsh::DrshServerStop;
using duetos::net::drsh::DrshSetPassword;
using duetos::net::drsh::DrshStatus;

namespace
{

bool StrEqLocal(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void WriteU64Dec(u64 v)
{
    char buf[24];
    u32 n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char rev[24];
        u32 r = 0;
        while (v > 0 && r < sizeof(rev))
        {
            rev[r++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (r > 0)
            buf[n++] = rev[--r];
    }
    buf[n] = '\0';
    ConsoleWrite(buf);
}

void PrintStatus()
{
    const DrshStatus s = DrshServerStatus();
    ConsoleWrite("DRSH: listener=");
    ConsoleWrite(s.running ? "running" : "stopped");
    ConsoleWrite(", password=");
    ConsoleWrite(s.password_set ? "set" : "unset");
    ConsoleWrite(", port=");
    WriteU64Dec(static_cast<u64>(s.listen_port));
    ConsoleWriteln("");
    ConsoleWrite("DRSH: session=");
    ConsoleWrite(s.session_active ? "active" : "idle");
    ConsoleWrite(", authenticated=");
    ConsoleWrite(s.authenticated ? "yes" : "no");
    ConsoleWriteln("");
    ConsoleWrite("DRSH: connections=");
    WriteU64Dec(s.connections_total);
    ConsoleWrite(", auth_failures=");
    WriteU64Dec(s.auth_failures_total);
    ConsoleWrite(", frames rx/tx=");
    WriteU64Dec(s.frames_rx);
    ConsoleWrite("/");
    WriteU64Dec(s.frames_tx);
    ConsoleWriteln("");
}

bool ParseU16(const char* s, u16* out)
{
    u32 v = 0;
    if (s == nullptr || *s == '\0')
        return false;
    while (*s != '\0')
    {
        if (*s < '0' || *s > '9')
            return false;
        v = v * 10 + static_cast<u32>(*s - '0');
        if (v > 0xFFFFu)
            return false;
        ++s;
    }
    *out = static_cast<u16>(v);
    return true;
}

} // namespace

void CmdDrshd(u32 argc, char** argv)
{
    if (argc < 2 || StrEqLocal(argv[1], "status") || StrEqLocal(argv[1], "info"))
    {
        PrintStatus();
        return;
    }
    if (StrEqLocal(argv[1], "passwd") || StrEqLocal(argv[1], "password"))
    {
        if (!RequireAdmin("DRSHD"))
            return;
        if (argc < 3)
        {
            ConsoleWriteln("DRSHD: usage: drshd passwd <password>");
            return;
        }
        if (!DrshSetPassword(argv[2]))
        {
            ConsoleWriteln("DRSHD: password not set (listener active, or too long)");
            return;
        }
        ConsoleWriteln("DRSHD: password updated");
        return;
    }
    if (StrEqLocal(argv[1], "start"))
    {
        if (!RequireAdmin("DRSHD"))
            return;
        u16 port = 0; // 0 = default
        if (argc >= 3)
        {
            if (!ParseU16(argv[2], &port))
            {
                ConsoleWriteln("DRSHD: malformed port");
                return;
            }
        }
        if (!DrshServerStart(port))
        {
            ConsoleWriteln("DRSHD: start failed (already running, no password, or socket layer refused)");
            return;
        }
        ConsoleWriteln("DRSHD: listener started");
        return;
    }
    if (StrEqLocal(argv[1], "stop"))
    {
        if (!RequireAdmin("DRSHD"))
            return;
        DrshServerStop();
        ConsoleWriteln("DRSHD: stop requested");
        return;
    }
    ConsoleWriteln("DRSHD: usage: drshd [status|start [port]|stop|passwd <pw>]");
}

} // namespace duetos::core::shell::internal
