#pragma once

/*
 * CustomOS — kernel stats heartbeat thread.
 *
 * A minimal observability primitive. Spawns a kernel thread that wakes
 * every N timer ticks and dumps scheduler + heap + frame-allocator
 * counters via klog at Info level. The thread name is "kheartbeat".
 *
 * Why land this now: boot logs show a healthy one-shot startup, but
 * silent issues (slow task leak, heap fragmentation creep, IRQ storm
 * on some pin) only surface if we have eyes on the counters. The
 * heartbeat is the kernel's "I'm alive and this is what I've been
 * doing" signal for any long-running debugging session.
 *
 * Not a metrics pipeline. Future work: structured event stream to a
 * userspace collector, ring-buffer so the last N heartbeats survive
 * a panic, rate-limiting when log volume becomes a problem. For v0
 * it's just printf-style lines every few seconds.
 *
 * Context: kernel. Spawned once from kernel_main after SchedInit.
 */

namespace customos::core
{

/// Start the kernel heartbeat thread. Exactly once. Panics if called
/// a second time (double-init = two threads emitting interleaved
/// stats, which is both wasteful and log-spammy).
void StartHeartbeatThread();

} // namespace customos::core
