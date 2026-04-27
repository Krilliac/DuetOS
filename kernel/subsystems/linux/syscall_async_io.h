#pragma once

/*
 * Cross-TU surface for the Linux async-I/O families: timerfd,
 * signalfd, and epoll.
 *
 *   state=7  → timerfd, first_cluster = timerfd pool index
 *   state=8  → signalfd, first_cluster = signalfd pool index
 *   state=9  → epoll instance, first_cluster = epoll pool index
 *
 * Read / close in syscall_io.cpp / syscall_file.cpp dispatch on
 * those state values; fork() in syscall_clone.cpp bumps refcounts
 * on the same indices so a child inherits live handles.
 */

#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// Timerfd pool — read returns u64 = expirations since last read.
// Writes are not allowed (-EBADF). Backed by a 16-slot pool that
// computes expirations from SchedNowTicks() every read; blocking
// reads use WaitQueueBlockTimeout against the next expiry deadline.
i64 TimerfdRead(u32 idx, u64 user_dst, u64 len);
void TimerfdRelease(u32 idx);
void TimerfdRetain(u32 idx);

// Signalfd pool — read returns 0 events on every probe (v0 has no
// signal delivery; the slot's mask is recorded but no signal source
// pushes events into it). Sub-GAP: callers blocking on a signalfd
// wait forever or until close, which matches Linux's "no pending
// signal" behaviour modulo the missing wake.
i64 SignalfdRead(u32 idx, u64 user_dst, u64 len);
void SignalfdRelease(u32 idx);
void SignalfdRetain(u32 idx);

// Epoll instance pool — no per-fd read/write surface. epoll_ctl /
// epoll_wait are the only entry points. Close is reachable through
// the shared DoClose state arm.
void EpollRelease(u32 idx);
void EpollRetain(u32 idx);

// Helper for DoEpollWait: probe whether a Linux fd is readable
// right now. Implemented over the existing pool surfaces:
//   - pipe-read / eventfd / socket: peek count
//   - regular file: always readable (cursor can advance)
//   - timerfd: expirations > 0
//   - signalfd: never readable in v0
// Returns the EPOLLIN bit (0x1) when readable; 0 otherwise.
u32 LinuxFdEpollReady(u32 fd, u32 interest_mask);

} // namespace duetos::subsystems::linux::internal
