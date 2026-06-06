#pragma once

#include "util/types.h"

/*
 * DuetOS — service manager (init / PID-1 equivalent), v0.
 *
 * WHAT
 *   A kernel-resident supervisor for the userland programs DuetOS
 *   launches at boot. It replaces the hand-unrolled `SpawnElfFile`
 *   blocks that used to live inline in boot_bringup.cpp with a single
 *   declarative manifest plus a supervisor task that:
 *
 *     - spawns every `autostart` service in manifest order at boot,
 *     - tracks each service's live state by polling the scheduler,
 *     - respawns crashed services whose policy is `Always`, with
 *       crash-loop protection (rate-limited like a fault domain),
 *     - exposes start / stop / restart / status to the `svc` shell
 *       command so an operator can drive the service set at runtime.
 *
 * WHY KERNEL-RESIDENT (not a /sbin/init ELF)
 *   DuetOS is a hybrid kernel whose long-running services (heartbeat,
 *   selfthink, the autonomic engine, serial-input) are already kernel
 *   tasks. A userland PID-1 would need ring-3 process-spawns-process
 *   plumbing that does not exist yet. The supervisor lives where the
 *   other system services live and drives userland processes through
 *   the same canonical `core::Spawn*File` API the shell `exec` and the
 *   desktop launcher use — one source of truth for "what runs at boot
 *   and what keeps it alive." When ring-3 self-spawn lands, a userland
 *   init can adopt this manifest without changing the descriptor shape.
 *
 * SCOPE (v0)
 *   - Services run with the trusted cap-set + trusted budgets, like
 *     the boot spawns they replace. A per-service sandbox profile is a
 *     future knob (GAP, below) — today every manifest entry is a
 *     kernel-shipped, kernel-trusted program.
 *   - Restart policy is Never (oneshot) or Always (respawn-on-exit).
 *     OnFailure (respawn only on non-zero exit) needs the exit code
 *     captured at reap time and is deferred.
 *   - Liveness is polled, not event-driven: the supervisor wakes on a
 *     ~1 s cadence. PIDs are monotonic (proc/process.cpp g_next_pid),
 *     so a poll-by-pid can never be fooled into adopting a reused id.
 *
 * Context: kernel. The manifest is a constant table; the runtime
 * table + supervisor task are owned by service.cpp and mutated only
 * from the supervisor task and the (scheduler-serialised) shell
 * command path.
 */

namespace duetos::core
{

// How a manifest entry's bytes are loaded into a ring-3 process.
enum class ServiceKind : u8
{
    NativeElf = 0, // native-ABI ELF64 via SpawnElfFile
    WinPe = 1,     // PE/COFF via SpawnPeFile (preloads Win32 DLL set)
};

// What the supervisor does when a service's process exits. (Named
// ...Policy so it doesn't collide with the ServiceRestart() control
// function below.)
enum class ServiceRestartPolicy : u8
{
    Never = 0,  // oneshot — run once, leave Exited (the v0 boot programs)
    Always = 1, // daemon — respawn on exit, rate-limited against crash loops
};

// Live state of a manifest entry.
enum class ServiceState : u8
{
    Stopped = 0, // never started, or stopped by the operator
    Running = 1, // process is on the scheduler's live lists
    Exited = 2,  // process left the live lists (oneshot done, or crashed)
    Failed = 3,  // respawn rate limit tripped — supervisor gave up
};

// Manifest descriptor — pure constant data. The byte/size accessors
// point at the ramfs blob the service is loaded from.
using ServiceBytesFn = const u8* (*)();
using ServiceSizeFn = u64 (*)();

struct ServiceDesc
{
    const char* name; // stable id used by the shell (e.g. "usershell")
    const char* path; // label handed to Spawn*File (e.g. "/bin/usershell.elf")
    ServiceKind kind; // ELF vs PE loader path
    ServiceRestartPolicy restart;
    bool autostart;       // spawn at ServiceManagerStartAll()
    ServiceBytesFn bytes; // ramfs blob pointer accessor
    ServiceSizeFn size;   // ramfs blob length accessor
};

// Crash-loop guard: a Always-service that exits more than this many
// times inside the window is marked Failed and no longer respawned.
// Same shape as the fault-domain restart throttle.
constexpr u32 kServiceRestartMax = 5;
constexpr u64 kServiceRestartWindowNs = 60ull * 1000ull * 1000ull * 1000ull; // 60 s

// Read-only status row for the `svc` command + diagnostics.
struct ServiceStatusView
{
    const char* name;
    ServiceState state;
    ServiceRestartPolicy restart;
    bool autostart;
    u64 pid;      // 0 if never spawned / not running
    u32 restarts; // lifetime respawn count
    u64 last_spawn_ns;
    u64 last_exit_ns;
};

/// Build the runtime table from the manifest. Idempotent. Does NOT
/// spawn anything. Safe to call from boot before the scheduler is
/// driving userland.
void ServiceManagerInit();

/// Spawn every `autostart` manifest entry, in order, and start the
/// supervisor task. Called once from boot_bringup at the point the
/// old inline spawn blocks ran. Idempotent — a second call only
/// (re)starts entries that are Stopped.
void ServiceManagerStartAll();

/// Operator controls (admin-gated by the shell command, not here).
/// All match the service by `name`; return false on unknown name.
bool ServiceStart(const char* name);   // spawn if Stopped/Exited/Failed
bool ServiceStop(const char* name);    // kill the process; clears Always respawn
bool ServiceRestart(const char* name); // stop (if running) then start

/// Supervisor poll: reconcile each service's recorded state with the
/// scheduler, and respawn Always-services that have exited. Called by
/// the supervisor task; exposed so a test/diag can step it directly.
void ServiceManagerTick();

/// Manifest size + indexed status read for `svc` / diag.
u32 ServiceCount();
bool ServiceStatusAt(u32 idx, ServiceStatusView* out);

/// Boot self-test for the restart-decision + crash-loop-backoff logic
/// (a pure function over synthetic timings — does not spawn). Emits a
/// PASS line so a healthy boot leaves grep-able proof; the supervisor
/// respawn path has no live daemon to exercise it at boot yet.
void ServiceManagerSelfTest();

} // namespace duetos::core
