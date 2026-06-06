#include "core/service.h"
#include "drivers/video/console.h"
#include "shell/shell_internal.h"
#include "util/string.h"
#include "util/types.h"

/*
 * Shell command — `svc` (service manager front-end).
 *
 * Sub-verbs:
 *   svc                       — list all services + live state (alias: list/status)
 *   svc start   <name>        — spawn a stopped/exited/failed service (admin)
 *   svc stop    <name>        — kill a running service, keep it down (admin)
 *   svc restart <name>        — stop (if up) then start (admin)
 *
 * Read-only listing is open to any logged-in user; mutating verbs are
 * admin-gated, mirroring `drshd`.
 */

namespace duetos::core::shell::internal
{

using duetos::core::ServiceCount;
using duetos::core::ServiceRestart; // control function (stop+start)
using duetos::core::ServiceRestartPolicy;
using duetos::core::ServiceStart;
using duetos::core::ServiceState;
using duetos::core::ServiceStatusAt;
using duetos::core::ServiceStatusView;
using duetos::core::ServiceStop;
using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteln;

namespace
{

const char* StateStr(ServiceState s)
{
    switch (s)
    {
    case ServiceState::Stopped:
        return "stopped";
    case ServiceState::Running:
        return "running";
    case ServiceState::Exited:
        return "exited";
    case ServiceState::Failed:
        return "failed";
    }
    return "?";
}

void PrintList()
{
    const u32 n = ServiceCount();
    ConsoleWriteln("NAME           STATE     POLICY  PID       RESTARTS");
    for (u32 i = 0; i < n; ++i)
    {
        ServiceStatusView v{};
        if (!ServiceStatusAt(i, &v))
            continue;
        ConsoleWrite(v.name);
        // pad name to ~15 cols for legibility.
        for (u32 p = StrLen(v.name); p < 15; ++p)
            ConsoleWrite(" ");
        ConsoleWrite(StateStr(v.state));
        for (u32 p = StrLen(StateStr(v.state)); p < 10; ++p)
            ConsoleWrite(" ");
        ConsoleWrite(v.restart == ServiceRestartPolicy::Always ? "always  " : "never   ");
        WriteU64Dec(v.pid);
        ConsoleWrite("        ");
        WriteU64Dec(static_cast<u64>(v.restarts));
        ConsoleWriteln("");
    }
}

} // namespace

void CmdSvc(u32 argc, char** argv)
{
    if (argc < 2 || StrEqual(argv[1], "list") || StrEqual(argv[1], "status"))
    {
        PrintList();
        return;
    }

    const bool is_start = StrEqual(argv[1], "start");
    const bool is_stop = StrEqual(argv[1], "stop");
    const bool is_restart = StrEqual(argv[1], "restart");
    if (is_start || is_stop || is_restart)
    {
        if (!RequireAdmin("SVC"))
            return;
        if (argc < 3)
        {
            ConsoleWriteln("SVC: usage: svc <start|stop|restart> <name>");
            return;
        }
        bool ok = false;
        if (is_start)
            ok = ServiceStart(argv[2]);
        else if (is_stop)
            ok = ServiceStop(argv[2]);
        else
            ok = ServiceRestart(argv[2]);
        if (!ok)
        {
            ConsoleWriteln("SVC: no such service (or action refused)");
            return;
        }
        ConsoleWrite("SVC: ");
        ConsoleWrite(argv[1]);
        ConsoleWrite(" ");
        ConsoleWriteln(argv[2]);
        return;
    }

    ConsoleWriteln("SVC: usage: svc [list|start <name>|stop <name>|restart <name>]");
}

} // namespace duetos::core::shell::internal
