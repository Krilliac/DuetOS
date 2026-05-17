/*
 * DuetOS — GDB `monitor` (qRcmd) command surface: dispatch,
 * MonitorWriter, control verbs, self-test. Read-introspection
 * verbs live in gdb_monitor_read.cpp (split for the size
 * threshold + isolation audit). See gdb_monitor.h for the
 * trust/isolation contract.
 */

#include "diag/gdb_monitor.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "debug/tripwire.h"
#include "debug/watch.h"
#include "diag/gdb_server.h"
#include "diag/kdbg.h"
#include "diag/minidump.h"
#include "util/string.h"

namespace duetos::diag
{

// ---------------------------------------------------------------------------
// MonitorWriter
// ---------------------------------------------------------------------------

MonitorWriter::MonitorWriter(char* buf, u32 cap) : m_buf(buf), m_cap(cap)
{
    if (m_buf != nullptr && m_cap != 0)
    {
        m_buf[0] = '\0';
    }
}

void MonitorWriter::Char(char c)
{
    if (m_buf == nullptr || m_pos + 1 >= m_cap)
    {
        m_truncated = true;
        return;
    }
    m_buf[m_pos++] = c;
    m_buf[m_pos] = '\0';
}

void MonitorWriter::Str(const char* s)
{
    if (s == nullptr)
    {
        return;
    }
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (m_pos + 1 >= m_cap)
        {
            m_truncated = true;
            return;
        }
        m_buf[m_pos++] = s[i];
    }
    if (m_buf != nullptr && m_pos < m_cap)
    {
        m_buf[m_pos] = '\0';
    }
}

void MonitorWriter::U64(u64 v)
{
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v != 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n != 0)
    {
        Char(tmp[--n]);
    }
}

void MonitorWriter::Hex(u64 v, u32 min_digits)
{
    char tmp[16];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v != 0 && n < sizeof(tmp))
    {
        const u32 nib = static_cast<u32>(v & 0xF);
        tmp[n++] = static_cast<char>(nib < 10 ? ('0' + nib) : ('a' + nib - 10));
        v >>= 4;
    }
    while (n < min_digits && n < sizeof(tmp))
    {
        tmp[n++] = '0';
    }
    while (n != 0)
    {
        Char(tmp[--n]);
    }
}

void MonitorWriter::Line()
{
    Char('\n');
}

// ---------------------------------------------------------------------------
// Tokenizer + small parse helpers
// ---------------------------------------------------------------------------

namespace
{

constexpr u32 kMaxArgs = 8;

// Split `src` into whitespace-delimited tokens (runs collapsed),
// pointing into the caller-owned mutable `line` copy. Returns argc.
u32 Tokenize(char* line, u32 len, const char** argv)
{
    u32 argc = 0;
    u32 i = 0;
    while (i < len && argc < kMaxArgs)
    {
        while (i < len && (line[i] == ' ' || line[i] == '\t'))
        {
            ++i;
        }
        if (i >= len || line[i] == '\0')
        {
            break;
        }
        argv[argc++] = &line[i];
        while (i < len && line[i] != ' ' && line[i] != '\t' && line[i] != '\0')
        {
            ++i;
        }
        if (i < len)
        {
            line[i++] = '\0';
        }
    }
    return argc;
}

// Pointer to the substring of `cmd` that follows the first
// `skip` whitespace-delimited tokens (used for `reg` whose path
// can itself contain spaces, e.g. "Windows NT"). Returns "" if
// fewer than `skip` tokens exist.
const char* RestAfter(const char* cmd, u32 skip)
{
    u32 i = 0;
    for (u32 t = 0; t < skip; ++t)
    {
        while (cmd[i] == ' ' || cmd[i] == '\t')
        {
            ++i;
        }
        if (cmd[i] == '\0')
        {
            return &cmd[i];
        }
        while (cmd[i] != '\0' && cmd[i] != ' ' && cmd[i] != '\t')
        {
            ++i;
        }
    }
    while (cmd[i] == ' ' || cmd[i] == '\t')
    {
        ++i;
    }
    return &cmd[i];
}

bool Eq(const char* a, const char* b)
{
    return core::StrEqual(a, b);
}

bool Contains(const char* hay, const char* needle)
{
    if (hay == nullptr || needle == nullptr || needle[0] == '\0')
    {
        return false;
    }
    for (u32 i = 0; hay[i] != '\0'; ++i)
    {
        u32 j = 0;
        while (needle[j] != '\0' && hay[i + j] == needle[j])
        {
            ++j;
        }
        if (needle[j] == '\0')
        {
            return true;
        }
    }
    return false;
}

// Parse a decimal or 0x-hex unsigned. Returns false on empty /
// malformed input so callers can reject it explicitly.
bool ParseU64(const char* s, u64* out)
{
    if (s == nullptr || s[0] == '\0')
    {
        return false;
    }
    u64 v = 0;
    u32 i = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        i = 2;
        if (s[i] == '\0')
        {
            return false;
        }
        for (; s[i] != '\0'; ++i)
        {
            const char c = s[i];
            u32 d;
            if (c >= '0' && c <= '9')
                d = static_cast<u32>(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = static_cast<u32>(10 + c - 'a');
            else if (c >= 'A' && c <= 'F')
                d = static_cast<u32>(10 + c - 'A');
            else
                return false;
            v = (v << 4) | d;
        }
    }
    else
    {
        for (; s[i] != '\0'; ++i)
        {
            if (s[i] < '0' || s[i] > '9')
            {
                return false;
            }
            v = v * 10 + static_cast<u64>(s[i] - '0');
        }
    }
    *out = v;
    return true;
}

void Usage(MonitorWriter& out)
{
    out.Str("DuetOS monitor — verb namespace 'duet'\n"
            "  duet help                 this text\n"
            "  duet ps                   processes (pid name state ticks regions)\n"
            "  duet caps <pid>           decode the capability bitset\n"
            "  duet threads              scheduler task list + stats\n"
            "  duet handles <pid>        IPC handle table summary\n"
            "  duet vm <pid>             address-space region map\n"
            "  duet mods <pid>           loaded PE/ELF (DLL) image map\n"
            "  duet win                  Win32 window list\n"
            "  duet win32 <pid>          per-process Win32 state\n"
            "  duet reg <ROOT> <path>    registry node (ROOT=HKLM|HKCU)\n"
            "  duet probe list|arm <name>|disarm <name>\n"
            "  duet kdbg list|mask|on <ch>|off <ch>\n"
            "  duet watch list|add <name> <hexaddr> <len> <act>|del <name>\n"
            "  duet trip list|del <name>\n"
            "  duet dump                 minidump from the stop-point context\n");
}

// ---- control verbs --------------------------------------------------------

void CmdProbe(u32 argc, const char** argv, MonitorWriter& out)
{
    if (argc >= 3 && Eq(argv[2], "list"))
    {
        debug::ProbeInfo info[static_cast<u64>(debug::ProbeId::kCount)];
        const u64 n = debug::ProbeList(info, static_cast<u64>(debug::ProbeId::kCount));
        for (u64 i = 0; i < n; ++i)
        {
            out.Str("  ");
            out.Str(info[i].name);
            out.Str("  arm=");
            out.U64(static_cast<u64>(info[i].arm));
            out.Str("  fires=");
            out.U64(info[i].fire_count);
            out.Line();
        }
        return;
    }
    const bool arm = (argc >= 4 && Eq(argv[2], "arm"));
    const bool disarm = (argc >= 4 && Eq(argv[2], "disarm"));
    if (arm || disarm)
    {
        const debug::ProbeId id = debug::ProbeByName(argv[3]);
        if (id == debug::ProbeId::kCount)
        {
            out.Str("probe: unknown probe '");
            out.Str(argv[3]);
            out.Str("'\n");
            return;
        }
        debug::ProbeSetArm(id, arm ? debug::ProbeArm::ArmedLog : debug::ProbeArm::Disarmed);
        out.Str(arm ? "probe armed: " : "probe disarmed: ");
        out.Str(argv[3]);
        out.Line();
        return;
    }
    out.Str("usage: duet probe list|arm <name>|disarm <name>\n");
}

void CmdKdbg(u32 argc, const char** argv, MonitorWriter& out)
{
    if (argc >= 3 && Eq(argv[2], "mask"))
    {
        out.Str("kdbg mask = 0x");
        out.Hex(core::DbgMask());
        out.Line();
        return;
    }
    if (argc >= 3 && Eq(argv[2], "list"))
    {
        for (core::DbgChannel ch = core::DbgChannelNext(core::DbgChannel::None); ch != core::DbgChannel::None;
             ch = core::DbgChannelNext(ch))
        {
            out.Str("  ");
            out.Str(core::DbgChannelName(ch));
            out.Str(core::DbgIsEnabled(ch) ? "  : on\n" : "  : off\n");
        }
        return;
    }
    const bool on = (argc >= 4 && Eq(argv[2], "on"));
    const bool off = (argc >= 4 && Eq(argv[2], "off"));
    if (on || off)
    {
        const core::DbgChannel ch = core::DbgChannelByName(argv[3]);
        if (ch == core::DbgChannel::None)
        {
            out.Str("kdbg: unknown channel '");
            out.Str(argv[3]);
            out.Str("'\n");
            return;
        }
        if (on)
            core::DbgEnable(static_cast<u32>(ch));
        else
            core::DbgDisable(static_cast<u32>(ch));
        out.Str(on ? "kdbg on: " : "kdbg off: ");
        out.Str(argv[3]);
        out.Line();
        return;
    }
    out.Str("usage: duet kdbg list|mask|on <ch>|off <ch>\n");
}

// Stable name pool for `watch add` — debug::Watch holds the name
// pointer (does not copy) and there are only 4 DR slots, so a
// 4-entry round-robin pool matches the hardware ceiling.
char g_watch_names[4][32];
u32 g_watch_name_next = 0;

void CmdWatch(u32 argc, const char** argv, MonitorWriter& out)
{
    if (argc >= 3 && Eq(argv[2], "list"))
    {
        debug::WatchInfo info[4];
        const usize n = debug::WatchList(info, 4);
        for (usize i = 0; i < n; ++i)
        {
            out.Str("  ");
            out.Str(info[i].name);
            out.Str("  addr=0x");
            out.Hex(info[i].addr);
            out.Str("  len=");
            out.U64(info[i].len_bytes);
            out.Str("  hits=");
            out.U64(info[i].hit_count);
            out.Line();
        }
        if (n == 0)
        {
            out.Str("  (no watchpoints)\n");
        }
        return;
    }
    if (argc >= 4 && Eq(argv[2], "del"))
    {
        out.Str(debug::WatchRemove(argv[3]) ? "watch removed: " : "watch: not found: ");
        out.Str(argv[3]);
        out.Line();
        return;
    }
    if (argc >= 5 && Eq(argv[2], "add"))
    {
        u64 addr = 0;
        u64 len = 8;
        if (!ParseU64(argv[4], &addr) || (argc >= 6 && !ParseU64(argv[5], &len)))
        {
            out.Str("watch: bad address/length\n");
            return;
        }
        if (len != 1 && len != 2 && len != 4 && len != 8)
        {
            out.Str("watch: length must be 1, 2, 4, or 8\n");
            return;
        }
        char* slot = g_watch_names[g_watch_name_next];
        g_watch_name_next = (g_watch_name_next + 1) % 4;
        u32 p = 0;
        core::AppendStr(slot, &p, 32, argv[3]);
        slot[(p < 32) ? p : 31] = '\0';
        const bool ok = debug::Watch(slot, reinterpret_cast<const void*>(addr), static_cast<u8>(len),
                                     debug::WatchAction::LogEachHit);
        out.Str(ok ? "watch added: " : "watch: install failed (slot/len/collision): ");
        out.Str(slot);
        out.Line();
        return;
    }
    out.Str("usage: duet watch list|add <name> <hexaddr> <len> <act>|del <name>\n");
}

void CmdTrip(u32 argc, const char** argv, MonitorWriter& out)
{
    if (argc >= 3 && Eq(argv[2], "list"))
    {
        debug::TripwireInfo info[16];
        const usize n = debug::TripwireList(info, 16);
        for (usize i = 0; i < n; ++i)
        {
            out.Str("  ");
            out.Str(info[i].name);
            out.Str("  addr=0x");
            out.Hex(info[i].addr);
            out.Str("  len=");
            out.U64(info[i].len_bytes);
            out.Str("  mism=");
            out.U64(info[i].mismatch_count);
            out.Line();
        }
        if (n == 0)
        {
            out.Str("  (no tripwires)\n");
        }
        return;
    }
    if (argc >= 4 && Eq(argv[2], "del"))
    {
        out.Str(debug::TripwireRemove(argv[3]) ? "tripwire removed: " : "tripwire: not found: ");
        out.Str(argv[3]);
        out.Line();
        return;
    }
    out.Str("usage: duet trip list|del <name>\n");
}

void CmdDump(MonitorWriter& out)
{
    const gdb::GdbServerRegSnapshot& s = gdb::GdbServerTrapSnapshot();
    minidump::EmitMinidump(s.rip, s.rsp, s.rbp, 0);
    out.Str("minidump emitted from stop-point context (rip=0x");
    out.Hex(s.rip);
    out.Str(" rsp=0x");
    out.Hex(s.rsp);
    out.Str(") — see QEMU debugcon → duetos.dmp\n");
}

} // namespace

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

bool GdbMonitorDispatch(const char* cmd, u32 cmd_len, MonitorWriter& out)
{
    if (cmd == nullptr)
    {
        return false;
    }

    static char line[1024];
    u32 ln = 0;
    for (u32 i = 0; i < cmd_len && cmd[i] != '\0' && ln + 1 < sizeof(line); ++i)
    {
        line[ln++] = cmd[i];
    }
    line[ln] = '\0';

    const char* argv[kMaxArgs] = {};
    const u32 argc = Tokenize(line, ln, argv);
    if (argc == 0 || !Eq(argv[0], "duet"))
    {
        return false;
    }
    if (argc == 1 || Eq(argv[1], "help"))
    {
        Usage(out);
        return true;
    }

    const char* sub = argv[1];
    u64 pid = 0;
    const bool have_pid = (argc >= 3) && ParseU64(argv[2], &pid);

    if (Eq(sub, "ps"))
    {
        mon_internal::CmdPs(out);
    }
    else if (Eq(sub, "threads"))
    {
        mon_internal::CmdThreads(out);
    }
    else if (Eq(sub, "win"))
    {
        mon_internal::CmdWin(out);
    }
    else if (Eq(sub, "caps") || Eq(sub, "handles") || Eq(sub, "vm") || Eq(sub, "mods") || Eq(sub, "win32"))
    {
        if (!have_pid)
        {
            out.Str(sub);
            out.Str(": usage: duet ");
            out.Str(sub);
            out.Str(" <pid>\n");
            return true;
        }
        if (Eq(sub, "caps"))
            mon_internal::CmdCaps(pid, out);
        else if (Eq(sub, "handles"))
            mon_internal::CmdHandles(pid, out);
        else if (Eq(sub, "vm"))
            mon_internal::CmdVm(pid, out);
        else if (Eq(sub, "mods"))
            mon_internal::CmdMods(pid, out);
        else
            mon_internal::CmdWin32(pid, out);
    }
    else if (Eq(sub, "reg"))
    {
        mon_internal::CmdReg(RestAfter(cmd, 2), out);
    }
    else if (Eq(sub, "probe"))
    {
        CmdProbe(argc, argv, out);
    }
    else if (Eq(sub, "kdbg"))
    {
        CmdKdbg(argc, argv, out);
    }
    else if (Eq(sub, "watch"))
    {
        CmdWatch(argc, argv, out);
    }
    else if (Eq(sub, "trip"))
    {
        CmdTrip(argc, argv, out);
    }
    else if (Eq(sub, "dump"))
    {
        CmdDump(out);
    }
    else
    {
        out.Str("duet: unknown command '");
        out.Str(sub);
        out.Str("' — try 'duet help'\n");
    }

    if (out.Truncated())
    {
        out.Str("\n[truncated]\n");
    }
    return true;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

void GdbMonitorSelfTest()
{
    char buf[2048];

    // help must list the verb surface.
    {
        MonitorWriter w(buf, sizeof(buf));
        if (!GdbMonitorDispatch("duet help", 9, w))
        {
            core::Panic("diag/gdb-monitor", "self-test: 'duet help' not recognized");
        }
        if (!Contains(w.Data(), "probe") || !Contains(w.Data(), "kdbg"))
        {
            core::Panic("diag/gdb-monitor", "self-test: help text missing expected verbs");
        }
    }

    // ps always has at least the boot task.
    {
        MonitorWriter w(buf, sizeof(buf));
        GdbMonitorDispatch("duet ps", 7, w);
        if (w.Len() == 0)
        {
            core::Panic("diag/gdb-monitor", "self-test: 'duet ps' produced no output");
        }
    }

    // non-"duet" lines must fall through to the unsupported reply.
    {
        MonitorWriter w(buf, sizeof(buf));
        if (GdbMonitorDispatch("info registers", 14, w))
        {
            core::Panic("diag/gdb-monitor", "self-test: non-duet line wrongly accepted");
        }
    }

    arch::SerialWrite("[gdb-monitor-selftest] PASS\n");
}

} // namespace duetos::diag
