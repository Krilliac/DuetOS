#pragma once

#include "util/types.h"

namespace duetos::sync
{
// Field-for-field mirror of kernel/sync/spinlock.h's SpinLock.
//
// It is a TICKET lock — (next_ticket, now_serving) free iff equal — and
// callers brace-initialise it with DESIGNATED initialisers naming those
// fields (e.g. kernel/net/socket.cpp's g_socket_lock). This shim used to
// declare a single `locked` word, so any fuzzed TU that named the real
// fields failed to compile with "field designator does not refer to any
// field". The names must track the kernel struct, not merely the size.
struct SpinLock
{
    volatile u32 next_ticket;
    volatile u32 now_serving;
    volatile u32 owner_cpu;
    u16 class_id;
};
struct IrqFlags
{
    u64 rflags;
};
inline IrqFlags SpinLockAcquire(SpinLock&)
{
    return IrqFlags{0};
}
inline void SpinLockRelease(SpinLock&, IrqFlags) {}

// RAII guard mirroring kernel/sync/spinlock.h. Fuzzed TUs that use the
// guard form (kernel/net/socket.cpp, kernel/subsystems/win32/section.cpp)
// link against THIS header, not the kernel one -- the fuzz Makefile puts
// `-I host_shim` ahead of `-I kernel` -- so anything the kernel header
// exposes and a fuzzed TU calls must be mirrored here or the build dies
// with "no member named 'SpinLockGuard'".
//
// Single-threaded by construction under libFuzzer, so acquire/release
// are no-ops; the guard exists to satisfy the shape, not to serialise.
class SpinLockGuard
{
  public:
    explicit SpinLockGuard(SpinLock& lock) : m_lock(&lock), m_flags(SpinLockAcquire(lock)) {}
    ~SpinLockGuard() { SpinLockRelease(*m_lock, m_flags); }
    SpinLockGuard(const SpinLockGuard&) = delete;
    SpinLockGuard& operator=(const SpinLockGuard&) = delete;

  private:
    SpinLock* m_lock;
    IrqFlags m_flags;
};
} // namespace duetos::sync
