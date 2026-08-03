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
 * those state values. fork() shares the exact KFile/OFD identity;
 * the pool index is never re-resolved through a numeric fd later.
 */

#include "util/types.h"

namespace duetos::core
{
struct LinuxFdAcquired;
struct Process;
} // namespace duetos::core

namespace duetos::subsystems::linux::internal
{

// Timerfd pool — read returns u64 = expirations since last read.
// Writes are not allowed (-EBADF). Backed by an 8-slot pool that
// computes expirations from SchedNowTicks() every read; blocking
// reads use a cancellable sequence/timed bridge against the next deadline.
i64 TimerfdRead(u32 idx, u64 user_dst, u64 len, bool nonblocking);
void TimerfdRelease(u32 idx);

// Signalfd pool — read drains matching bits from the current
// process pending-signal bitmap into signalfd_siginfo records. v0
// does not retain queued sender metadata. Blocking reads use the owning
// Process signal sequence; O_NONBLOCK returns -EAGAIN immediately.
i64 SignalfdRead(u32 idx, u64 user_dst, u64 len, bool nonblocking);
void SignalfdRelease(u32 idx);

// Epoll instance pool — no per-fd read/write surface. epoll_ctl /
// epoll_wait are the only entry points. Close is reachable through
// the shared DoClose state arm.
void EpollRelease(u32 idx);

// Helper for DoEpollWait / DoPoll: probe whether a retained Linux fd is readable
// right now. Implemented over the existing pool surfaces:
//   - pipe-read / eventfd / socket: peek count
//   - regular file: always readable (cursor can advance)
//   - timerfd: expirations > 0
//   - signalfd: matching process-pending signal bits
// Returns the EPOLLIN bit (0x1) when readable; 0 otherwise.
u32 LinuxFdEpollReady(const core::LinuxFdAcquired& acquired, u32 interest_mask, core::Process* signal_owner);

} // namespace duetos::subsystems::linux::internal
