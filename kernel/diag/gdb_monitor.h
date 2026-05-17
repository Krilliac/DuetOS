#pragma once

#include "util/types.h"

/*
 * DuetOS — GDB `monitor` (qRcmd) command surface.
 *
 * WHAT
 *   The generic GDB remote-serial server (kernel/diag/gdb_server.*)
 *   speaks raw registers / memory / breakpoints. Stock GDB cannot
 *   express DuetOS-specific state (capability bitsets, IPC handle
 *   tables, the Win32 window manager, probes, kdbg channels, …).
 *   This TU implements a `duet <verb> [args]` command surface
 *   delivered over the standard GDB `qRcmd,<hex>` ("monitor")
 *   packet, so a specialized client OR stock `gdb` (`monitor duet
 *   …`) gets the full introspection + debug-facility control.
 *
 * TRUST MODEL
 *   The monitor surface inherits the SAME boundary as the already-
 *   shipped `M` / `G` write packets: any client that can reach the
 *   COM2 RSP socket while the target is stopped already has
 *   unauthenticated memory/register write. Read introspection +
 *   debug-facility control does not widen that boundary, so NO
 *   `kCapDebug` check is added here — there is no authenticated
 *   principal on a raw serial transport, and a cap check would be
 *   a probe-satisfying facade.
 *
 * ISOLATION
 *   Code here only READS subsystem state via public kernel APIs
 *   (widget.h, custom.h, handle_table.h, registry.h's RegistryQuery)
 *   and never mutates subsystem internals. Mutating verbs act only
 *   on kernel-owned debug facilities (probes / kdbg / watch /
 *   tripwire / minidump).
 *
 * STOP-LOOP ONLY
 *   qRcmd is dispatched from inside the GDB stop loop, so monitor
 *   commands only run while the target is stopped — exactly the
 *   same constraint stock `monitor` has.
 */

namespace duetos::diag
{

/// Bounded text builder for monitor replies. Stops writing on
/// overflow and latches `truncated_`; never writes out of bounds.
/// NUL-terminates on every mutation so `Data()` is always a valid
/// C string.
class MonitorWriter
{
  public:
    MonitorWriter(char* buf, u32 cap);

    void Str(const char* s);
    void Char(char c);
    void U64(u64 v);                     // decimal
    void Hex(u64 v, u32 min_digits = 0); // lowercase, no "0x"
    void Line();                         // emits '\n'

    bool Truncated() const { return m_truncated; }
    u32 Len() const { return m_pos; }
    const char* Data() const { return m_buf; }

  private:
    char* m_buf;
    u32 m_cap;
    u32 m_pos = 0;
    bool m_truncated = false;
};

/// Execute one decoded monitor command line. Returns true when
/// `cmd` was a recognized `duet …` line (the reply is in `out`,
/// even for an unknown subcommand — a friendly usage hint).
/// Returns false ONLY when `cmd` is not a `duet` line at all, so
/// the caller can answer the GDB packet with the empty
/// "unsupported" reply.
bool GdbMonitorDispatch(const char* cmd, u32 cmd_len, MonitorWriter& out);

/// Boot-time self-test. Exercises the dispatcher directly (no
/// gdb_server I/O) and emits a grep-able `[gdb-monitor-selftest]
/// PASS` line. Panics on failure.
void GdbMonitorSelfTest();

namespace mon_internal
{
// Read-introspection verbs. Defined in gdb_monitor_read.cpp; the
// dispatch table in gdb_monitor.cpp routes here. Split out so the
// read-only subsystem-API consumers live in one TU for the
// isolation audit, and each TU stays under the size threshold.
void CmdPs(MonitorWriter& out);
void CmdCaps(u64 pid, MonitorWriter& out);
void CmdThreads(MonitorWriter& out);
void CmdHandles(u64 pid, MonitorWriter& out);
void CmdVm(u64 pid, MonitorWriter& out);
void CmdMods(u64 pid, MonitorWriter& out);
void CmdWin(MonitorWriter& out);
void CmdWin32(u64 pid, MonitorWriter& out);
void CmdReg(const char* args, MonitorWriter& out);
} // namespace mon_internal

} // namespace duetos::diag
