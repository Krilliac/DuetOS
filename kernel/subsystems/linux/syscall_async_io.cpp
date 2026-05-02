/*
 * Linux async-I/O families — timerfd, signalfd, epoll. v0.
 *
 * Three new LinuxFd kinds (state values 7, 8, 9) — read / close
 * dispatch arms wired in syscall_io.cpp / syscall_file.cpp; fork
 * inheritance wired in syscall_clone.cpp.
 *
 * Pools are kernel-resident, fixed-cap (8 each — these are
 * test-grade engines and a typical caller holds at most one or two
 * instances at a time).
 *
 * Engine sketches:
 *
 *   timerfd  — itimerspec converted to scheduler-tick units;
 *              expirations counted from SchedNowTicks()
 *              + interval. Read returns u64 = expirations
 *              accumulated since the last read; blocks via
 *              WaitQueueBlockTimeout against the next deadline,
 *              so the timer-tick path itself doesn't need a
 *              dedicated callback.
 *
 *   signalfd — slot stores the caller's mask. v0 has no signal
 *              delivery, so SignalfdRead always reports "no events
 *              pending" — non-blocking returns -EAGAIN, blocking
 *              waits forever (or until close). Sub-GAP, fixed
 *              when a real signal-delivery path lands.
 *
 *   epoll    — instance + dynamic watch table (16 slots / inst).
 *              epoll_wait polls every watched fd via the readiness
 *              helpers exposed by the pipe / eventfd / socket /
 *              timerfd surfaces, then SchedSleepTicks(1) and
 *              repeats until either the timeout expires or any
 *              watch fires. Polling cadence is 10 ms; sub-GAP for
 *              callers that need lower latency (real Linux uses
 *              fd-side wake hooks).
 *
 * No O_NONBLOCK / EFD_CLOEXEC / TFD_NONBLOCK enforcement in v0 —
 * flags accepted, behaviour identical to the unflagged form.
 */

#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kTimerfdPoolCap = 8;
constexpr u32 kSignalfdPoolCap = 8;
constexpr u32 kEpollPoolCap = 8;
constexpr u32 kEpollWatchCap = 16;

// 100 Hz scheduler tick → 10 ms per tick → 10_000_000 ns per tick.
constexpr u64 kTickNs = 10'000'000ull;

// Linux epoll event-bit subset we honour. Real Linux exposes more,
// but EPOLLIN / EPOLLOUT / EPOLLERR / EPOLLHUP are what every
// blocking polyfill checks for.
constexpr u32 kEPOLLIN = 0x001;
constexpr u32 kEPOLLOUT = 0x004;
constexpr u32 kEPOLLERR = 0x008;
constexpr u32 kEPOLLHUP = 0x010;

struct Timerfd
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u64 next_expiry_tick; // SchedNowTicks() target; 0 = disarmed
    u64 interval_ticks;   // 0 = one-shot
    u64 expirations;      // accumulated since last read
    u32 clock_id;
    u32 _pad2;
    sched::WaitQueue read_wq;
};

struct Signalfd
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u64 mask;
    sched::WaitQueue read_wq;
};

struct EpollWatch
{
    bool in_use;
    u8 _pad[3];
    u32 fd;
    u32 events; // EPOLLIN / EPOLLOUT / EPOLLERR / EPOLLHUP
    u32 _pad2;
    u64 user_data; // epoll_event.data — opaque to us
};

struct Epoll
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u32 watch_count;
    u32 _pad2;
    EpollWatch watches[kEpollWatchCap];
};

Timerfd g_timerfd_pool[kTimerfdPoolCap];
Signalfd g_signalfd_pool[kSignalfdPoolCap];
Epoll g_epoll_pool[kEpollPoolCap];

i32 TimerfdAlloc(u32 clock_id)
{
    arch::Cli();
    for (u32 i = 0; i < kTimerfdPoolCap; ++i)
    {
        if (!g_timerfd_pool[i].in_use)
        {
            Timerfd& t = g_timerfd_pool[i];
            t.in_use = true;
            t.refs = 1;
            t.next_expiry_tick = 0;
            t.interval_ticks = 0;
            t.expirations = 0;
            t.clock_id = clock_id;
            t.read_wq.head = nullptr;
            t.read_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

i32 SignalfdAlloc(u64 mask)
{
    arch::Cli();
    for (u32 i = 0; i < kSignalfdPoolCap; ++i)
    {
        if (!g_signalfd_pool[i].in_use)
        {
            Signalfd& s = g_signalfd_pool[i];
            s.in_use = true;
            s.refs = 1;
            s.mask = mask;
            s.read_wq.head = nullptr;
            s.read_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

i32 EpollAlloc()
{
    arch::Cli();
    for (u32 i = 0; i < kEpollPoolCap; ++i)
    {
        if (!g_epoll_pool[i].in_use)
        {
            Epoll& e = g_epoll_pool[i];
            e.in_use = true;
            e.refs = 1;
            e.watch_count = 0;
            for (u32 w = 0; w < kEpollWatchCap; ++w)
                e.watches[w].in_use = false;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

// Catch up `expirations` based on the current tick. Caller must hold
// arch::Cli on entry.
void TimerfdAccrueExpirationsLocked(Timerfd& t, u64 now_ticks)
{
    if (t.next_expiry_tick == 0)
        return;
    if (now_ticks < t.next_expiry_tick)
        return;
    if (t.interval_ticks == 0)
    {
        // One-shot timer — single expiration, then disarm.
        ++t.expirations;
        t.next_expiry_tick = 0;
        return;
    }
    // Periodic — count every period that fits in the elapsed window.
    const u64 missed = (now_ticks - t.next_expiry_tick) / t.interval_ticks + 1;
    t.expirations += missed;
    t.next_expiry_tick += missed * t.interval_ticks;
}

} // namespace

// ============================================================
// Timerfd
// ============================================================

void TimerfdRetain(u32 idx)
{
    if (idx >= kTimerfdPoolCap)
        return;
    arch::Cli();
    Timerfd& t = g_timerfd_pool[idx];
    if (t.in_use)
        ++t.refs;
    arch::Sti();
}

void TimerfdRelease(u32 idx)
{
    if (idx >= kTimerfdPoolCap)
        return;
    arch::Cli();
    Timerfd& t = g_timerfd_pool[idx];
    if (!t.in_use || t.refs == 0)
    {
        arch::Sti();
        return;
    }
    --t.refs;
    if (t.refs == 0)
    {
        sched::WaitQueueWakeAll(&t.read_wq);
        t.in_use = false;
        t.next_expiry_tick = 0;
        t.interval_ticks = 0;
        t.expirations = 0;
    }
    arch::Sti();
}

i64 TimerfdRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kTimerfdPoolCap)
        return kEINVAL;
    if (len < 8)
        return kEINVAL; // timerfd reads are u64-sized
    Timerfd& t = g_timerfd_pool[idx];
    arch::Cli();
    while (t.in_use)
    {
        TimerfdAccrueExpirationsLocked(t, sched::SchedNowTicks());
        if (t.expirations > 0)
            break;
        if (t.next_expiry_tick == 0)
        {
            // Disarmed and no expirations — block until armed/closed.
            sched::WaitQueueBlock(&t.read_wq);
            arch::Cli();
            continue;
        }
        const u64 now = sched::SchedNowTicks();
        const u64 wait = (t.next_expiry_tick > now) ? (t.next_expiry_tick - now) : 1;
        sched::WaitQueueBlockTimeout(&t.read_wq, wait);
        arch::Cli();
    }
    if (!t.in_use)
    {
        arch::Sti();
        return 0;
    }
    const u64 expirations = t.expirations;
    t.expirations = 0;
    arch::Sti();
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), &expirations, sizeof(expirations)))
        return kEFAULT;
    return 8;
}

i64 DoTimerfdCreate(u64 clockid, u64 flags)
{
    (void)flags; // TFD_NONBLOCK / TFD_CLOEXEC accepted but not enforced
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 fd = 16;
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            fd = i;
            break;
        }
    }
    if (fd == 16)
        return kEMFILE;
    const i32 idx = TimerfdAlloc(static_cast<u32>(clockid));
    if (idx < 0)
        return kENFILE;
    p->linux_fds[fd].state = 7;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/timerfd] fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

namespace
{

struct Itimerspec
{
    i64 it_interval_sec;
    i64 it_interval_nsec;
    i64 it_value_sec;
    i64 it_value_nsec;
};

u64 ItimerspecToTicks(i64 sec, i64 nsec)
{
    if (sec < 0 || nsec < 0)
        return 0;
    const u64 total_ns = static_cast<u64>(sec) * 1'000'000'000ull + static_cast<u64>(nsec);
    if (total_ns == 0)
        return 0;
    return (total_ns + kTickNs - 1) / kTickNs;
}

void TicksToItimerspec(u64 ticks, i64& sec_out, i64& nsec_out)
{
    const u64 total_ns = ticks * kTickNs;
    sec_out = static_cast<i64>(total_ns / 1'000'000'000ull);
    nsec_out = static_cast<i64>(total_ns % 1'000'000'000ull);
}

} // namespace

i64 DoTimerfdSettime(u64 fd, u64 flags, u64 user_new, u64 user_old)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 7)
        return kEBADF;
    const u32 idx = p->linux_fds[fd].first_cluster;
    if (idx >= kTimerfdPoolCap)
        return kEINVAL;
    Itimerspec new_spec;
    if (!mm::CopyFromUser(&new_spec, reinterpret_cast<const void*>(user_new), sizeof(new_spec)))
        return kEFAULT;
    if (new_spec.it_value_nsec >= 1'000'000'000 || new_spec.it_interval_nsec >= 1'000'000'000)
        return kEINVAL;
    const u64 first_ticks = ItimerspecToTicks(new_spec.it_value_sec, new_spec.it_value_nsec);
    const u64 interval_ticks = ItimerspecToTicks(new_spec.it_interval_sec, new_spec.it_interval_nsec);
    constexpr u64 kTfdTimerAbstime = 0x1;
    arch::Cli();
    Timerfd& t = g_timerfd_pool[idx];
    if (!t.in_use)
    {
        arch::Sti();
        return kEBADF;
    }
    if (user_old != 0)
    {
        Itimerspec old_spec{};
        const u64 now = sched::SchedNowTicks();
        if (t.next_expiry_tick > now)
            TicksToItimerspec(t.next_expiry_tick - now, old_spec.it_value_sec, old_spec.it_value_nsec);
        TicksToItimerspec(t.interval_ticks, old_spec.it_interval_sec, old_spec.it_interval_nsec);
        arch::Sti();
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old_spec, sizeof(old_spec)))
            return kEFAULT;
        arch::Cli();
        if (!t.in_use)
        {
            arch::Sti();
            return kEBADF;
        }
    }
    if (first_ticks == 0)
    {
        // Disarm.
        t.next_expiry_tick = 0;
        t.interval_ticks = 0;
    }
    else
    {
        const u64 now = sched::SchedNowTicks();
        if ((flags & kTfdTimerAbstime) != 0)
            t.next_expiry_tick = first_ticks; // absolute tick value (caller-side).
        else
            t.next_expiry_tick = now + first_ticks;
        t.interval_ticks = interval_ticks;
    }
    t.expirations = 0;
    sched::WaitQueueWakeAll(&t.read_wq);
    arch::Sti();
    return 0;
}

i64 DoTimerfdGettime(u64 fd, u64 user_curr)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 7)
        return kEBADF;
    const u32 idx = p->linux_fds[fd].first_cluster;
    if (idx >= kTimerfdPoolCap)
        return kEINVAL;
    Itimerspec out{};
    arch::Cli();
    Timerfd& t = g_timerfd_pool[idx];
    if (!t.in_use)
    {
        arch::Sti();
        return kEBADF;
    }
    const u64 now = sched::SchedNowTicks();
    if (t.next_expiry_tick > now)
        TicksToItimerspec(t.next_expiry_tick - now, out.it_value_sec, out.it_value_nsec);
    TicksToItimerspec(t.interval_ticks, out.it_interval_sec, out.it_interval_nsec);
    arch::Sti();
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_curr), &out, sizeof(out)))
        return kEFAULT;
    return 0;
}

// ============================================================
// Signalfd
// ============================================================

void SignalfdRetain(u32 idx)
{
    if (idx >= kSignalfdPoolCap)
        return;
    arch::Cli();
    Signalfd& s = g_signalfd_pool[idx];
    if (s.in_use)
        ++s.refs;
    arch::Sti();
}

void SignalfdRelease(u32 idx)
{
    if (idx >= kSignalfdPoolCap)
        return;
    arch::Cli();
    Signalfd& s = g_signalfd_pool[idx];
    if (!s.in_use || s.refs == 0)
    {
        arch::Sti();
        return;
    }
    --s.refs;
    if (s.refs == 0)
    {
        sched::WaitQueueWakeAll(&s.read_wq);
        s.in_use = false;
        s.mask = 0;
    }
    arch::Sti();
}

i64 SignalfdRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kSignalfdPoolCap)
        return kEINVAL;
    if (len < 128) // sizeof(struct signalfd_siginfo)
        return kEINVAL;
    Signalfd& s = g_signalfd_pool[idx];
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;
    arch::Cli();
    if (!s.in_use)
    {
        arch::Sti();
        return 0;
    }
    // Walk the pending bitmap; emit one signalfd_siginfo per
    // matching signum, clear the bit. Caller-supplied buffer
    // determines how many we can emit (each record = 128 bytes).
    u8 stage[256];
    u64 emitted = 0;
    for (u32 sig = 1; sig < 64 && emitted + 128 <= len && emitted + 128 <= sizeof(stage); ++sig)
    {
        const u64 bit = (1ULL << sig);
        if ((p->linux_pending_signals & bit) == 0)
            continue;
        if ((s.mask & bit) == 0)
            continue;
        // struct signalfd_siginfo — Linux-stable, 128 bytes.
        // First 32 bytes carry the fields callers actually read:
        //   u32 ssi_signo; i32 ssi_errno; i32 ssi_code; u32 ssi_pid;
        //   u32 ssi_uid; i32 ssi_fd; u32 ssi_tid; u32 ssi_band;
        //   u32 ssi_overrun; u32 ssi_trapno; i32 ssi_status; ...
        // Padding to 128 with zeros.
        u8* rec = stage + emitted;
        for (u32 i = 0; i < 128; ++i)
            rec[i] = 0;
        const u32 sig_u32 = sig;
        for (u32 i = 0; i < 4; ++i)
            rec[i] = static_cast<u8>((sig_u32 >> (i * 8)) & 0xFF);
        // ssi_pid + ssi_uid not tracked per-signal in v0 — leave 0.
        p->linux_pending_signals &= ~bit;
        emitted += 128;
    }
    arch::Sti();
    if (emitted == 0)
        return kEAGAIN;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, emitted))
        return kEFAULT;
    return static_cast<i64>(emitted);
}

i64 DoSignalfd(u64 fd, u64 user_mask, u64 sigsetsize, u64 flags)
{
    (void)flags;
    if (sigsetsize > sizeof(u64))
        return kEINVAL;
    u64 mask = 0;
    if (user_mask != 0)
    {
        if (!mm::CopyFromUser(&mask, reinterpret_cast<const void*>(user_mask), sigsetsize))
            return kEFAULT;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    if (fd != static_cast<u64>(-1))
    {
        // Update existing signalfd's mask in place.
        if (fd >= 16 || p->linux_fds[fd].state != 8)
            return kEINVAL;
        const u32 idx = p->linux_fds[fd].first_cluster;
        if (idx >= kSignalfdPoolCap)
            return kEINVAL;
        arch::Cli();
        if (g_signalfd_pool[idx].in_use)
            g_signalfd_pool[idx].mask = mask;
        arch::Sti();
        return static_cast<i64>(fd);
    }
    u32 new_fd = 16;
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            new_fd = i;
            break;
        }
    }
    if (new_fd == 16)
        return kEMFILE;
    const i32 idx = SignalfdAlloc(mask);
    if (idx < 0)
        return kENFILE;
    p->linux_fds[new_fd].state = 8;
    p->linux_fds[new_fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[new_fd].size = 0;
    p->linux_fds[new_fd].offset = 0;
    p->linux_fds[new_fd].path[0] = '\0';
    arch::SerialWrite("[linux/signalfd] fd=");
    arch::SerialWriteHex(new_fd);
    arch::SerialWrite(" mask=");
    arch::SerialWriteHex(mask);
    arch::SerialWrite("\n");
    return static_cast<i64>(new_fd);
}

// ============================================================
// Epoll
// ============================================================

void EpollRetain(u32 idx)
{
    if (idx >= kEpollPoolCap)
        return;
    arch::Cli();
    Epoll& e = g_epoll_pool[idx];
    if (e.in_use)
        ++e.refs;
    arch::Sti();
}

void EpollRelease(u32 idx)
{
    if (idx >= kEpollPoolCap)
        return;
    arch::Cli();
    Epoll& e = g_epoll_pool[idx];
    if (!e.in_use || e.refs == 0)
    {
        arch::Sti();
        return;
    }
    --e.refs;
    if (e.refs == 0)
    {
        e.in_use = false;
        e.watch_count = 0;
        for (u32 w = 0; w < kEpollWatchCap; ++w)
            e.watches[w].in_use = false;
    }
    arch::Sti();
}

u32 LinuxFdEpollReady(u32 fd, u32 interest_mask)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return 0;
    const auto& slot = p->linux_fds[fd];
    if (slot.state == 0)
        return kEPOLLERR | kEPOLLHUP;
    u32 ready = 0;
    switch (slot.state)
    {
    case 1: // tty
        ready = (interest_mask & kEPOLLOUT);
        break;
    case 2: // regular file — always readable + writable
        ready = (interest_mask & (kEPOLLIN | kEPOLLOUT));
        break;
    case 3: // pipe-read
        if ((interest_mask & kEPOLLIN) && PipeReadReady(slot.first_cluster))
            ready |= kEPOLLIN;
        break;
    case 4: // pipe-write
        if ((interest_mask & kEPOLLOUT) && PipeWriteReady(slot.first_cluster))
            ready |= kEPOLLOUT;
        break;
    case 5: // eventfd
        if ((interest_mask & kEPOLLIN) && EventfdReady(slot.first_cluster))
            ready |= kEPOLLIN;
        if (interest_mask & kEPOLLOUT) // eventfd writes never block in v0
            ready |= kEPOLLOUT;
        break;
    case 6: // socket
        if ((interest_mask & kEPOLLIN) && SocketFdReadReady(slot.first_cluster))
            ready |= kEPOLLIN;
        if (interest_mask & kEPOLLOUT) // sockets never block writes in v0 (saturating)
            ready |= kEPOLLOUT;
        break;
    case 7: // timerfd
    {
        if (interest_mask & kEPOLLIN)
        {
            arch::Cli();
            Timerfd& t = g_timerfd_pool[slot.first_cluster];
            if (t.in_use)
            {
                TimerfdAccrueExpirationsLocked(t, sched::SchedNowTicks());
                if (t.expirations > 0)
                    ready |= kEPOLLIN;
            }
            arch::Sti();
        }
        break;
    }
    case 8: // signalfd — never readable in v0
        break;
    case 9: // epoll instance — never readable through epoll
        break;
    case 12: // pidfd — readable iff target process has exited
        if (interest_mask & kEPOLLIN)
        {
            const u64 target_pid = slot.first_cluster;
            // Two terminal states count as "exited":
            //   - target on g_zombies (DoExit done, not yet reaped)
            //   - SchedFindProcessByPid returns nullptr (already
            //     reaped or never existed)
            // Unreaped-zombie is the common case for shells that
            // poll a pidfd before wait4; reaped-already covers
            // races where wait4 ran first.
            if (sched::SchedIsPidZombie(target_pid))
            {
                ready |= kEPOLLIN;
            }
            else
            {
                core::Process* tgt = sched::SchedFindProcessByPid(target_pid);
                if (tgt == nullptr)
                    ready |= kEPOLLIN;
            }
        }
        break;
    default:
        break;
    }
    return ready;
}

i64 DoEpollCreate(u64 size)
{
    (void)size;
    return DoEpollCreate1(0);
}

i64 DoEpollCreate1(u64 flags)
{
    (void)flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 fd = 16;
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            fd = i;
            break;
        }
    }
    if (fd == 16)
        return kEMFILE;
    const i32 idx = EpollAlloc();
    if (idx < 0)
        return kENFILE;
    p->linux_fds[fd].state = 9;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/epoll] fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

namespace
{

// Linux struct epoll_event uses __attribute__((packed)) on x86 —
// total 12 bytes (4-byte events + 8-byte data). Match that exactly.
struct __attribute__((packed)) EpollEvent
{
    u32 events;
    u64 data;
};

} // namespace

i64 DoEpollCtl(u64 epfd, u64 op, u64 fd, u64 user_event)
{
    constexpr u64 kEpollCtlAdd = 1;
    constexpr u64 kEpollCtlDel = 2;
    constexpr u64 kEpollCtlMod = 3;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || epfd >= 16 || p->linux_fds[epfd].state != 9)
        return kEBADF;
    if (fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    const u32 idx = p->linux_fds[epfd].first_cluster;
    if (idx >= kEpollPoolCap)
        return kEINVAL;
    EpollEvent ev{};
    if (op != kEpollCtlDel && user_event != 0)
    {
        if (!mm::CopyFromUser(&ev, reinterpret_cast<const void*>(user_event), sizeof(ev)))
            return kEFAULT;
    }
    arch::Cli();
    Epoll& e = g_epoll_pool[idx];
    if (!e.in_use)
    {
        arch::Sti();
        return kEBADF;
    }
    // Search for an existing watch on this fd.
    i32 found = -1;
    for (u32 w = 0; w < kEpollWatchCap; ++w)
        if (e.watches[w].in_use && e.watches[w].fd == fd)
        {
            found = static_cast<i32>(w);
            break;
        }
    if (op == kEpollCtlAdd)
    {
        if (found >= 0)
        {
            arch::Sti();
            return -17; // -EEXIST
        }
        for (u32 w = 0; w < kEpollWatchCap; ++w)
        {
            if (!e.watches[w].in_use)
            {
                e.watches[w].in_use = true;
                e.watches[w].fd = static_cast<u32>(fd);
                e.watches[w].events = ev.events;
                e.watches[w].user_data = ev.data;
                ++e.watch_count;
                arch::Sti();
                return 0;
            }
        }
        arch::Sti();
        return kENOMEM;
    }
    if (op == kEpollCtlDel)
    {
        if (found < 0)
        {
            arch::Sti();
            return kENOENT;
        }
        e.watches[found].in_use = false;
        --e.watch_count;
        arch::Sti();
        return 0;
    }
    if (op == kEpollCtlMod)
    {
        if (found < 0)
        {
            arch::Sti();
            return kENOENT;
        }
        e.watches[found].events = ev.events;
        e.watches[found].user_data = ev.data;
        arch::Sti();
        return 0;
    }
    arch::Sti();
    return kEINVAL;
}

i64 DoEpollWait(u64 epfd, u64 user_events, u64 maxevents, u64 timeout_ms)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || epfd >= 16 || p->linux_fds[epfd].state != 9)
        return kEBADF;
    if (maxevents == 0)
        return kEINVAL;
    if (maxevents > 64)
        maxevents = 64;
    const u32 idx = p->linux_fds[epfd].first_cluster;
    if (idx >= kEpollPoolCap)
        return kEINVAL;
    // Convert timeout_ms (signed by caller convention; -1 = infinite)
    // into a tick budget. 10 ms per tick, round up so a 1 ms timeout
    // still polls once before returning.
    const i64 timeout_signed = static_cast<i64>(timeout_ms);
    bool infinite = false;
    u64 deadline_tick = 0;
    if (timeout_signed < 0)
        infinite = true;
    else
    {
        const u64 ticks = (timeout_signed + 9) / 10;
        deadline_tick = sched::SchedNowTicks() + ticks;
    }
    EpollEvent out_buf[64];
    while (true)
    {
        u32 hits = 0;
        arch::Cli();
        Epoll& e = g_epoll_pool[idx];
        if (!e.in_use)
        {
            arch::Sti();
            return kEBADF;
        }
        const u32 watch_count_snap = e.watch_count;
        if (watch_count_snap == 0)
        {
            arch::Sti();
            // Empty epoll set — block until timeout (Linux returns 0
            // immediately if no watches, but we mimic the more useful
            // "wait for the timeout" so callers can throttle loops
            // through an empty epoll). Fall through to sleep.
        }
        else
        {
            EpollWatch snap[kEpollWatchCap];
            for (u32 w = 0; w < kEpollWatchCap; ++w)
                snap[w] = e.watches[w];
            arch::Sti();
            for (u32 w = 0; w < kEpollWatchCap && hits < maxevents; ++w)
            {
                if (!snap[w].in_use)
                    continue;
                const u32 ready = LinuxFdEpollReady(snap[w].fd, snap[w].events);
                if (ready != 0)
                {
                    out_buf[hits].events = ready;
                    out_buf[hits].data = snap[w].user_data;
                    ++hits;
                }
            }
        }
        if (watch_count_snap > 0)
        {
            // Already released cli during snap copy — no-op here.
        }
        if (hits > 0)
        {
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_events), out_buf, hits * sizeof(EpollEvent)))
                return kEFAULT;
            return static_cast<i64>(hits);
        }
        // If the watch set includes a pidfd, prefer blocking on
        // the pidfd-exit waitqueue: any process exit wakes us
        // immediately and we re-evaluate readiness. For watch
        // sets without a pidfd, fall back to the timer cadence
        // so unrelated fd state changes still get the 100 ms
        // poll-and-recheck. Sub-GAP: only pidfd has a real wake
        // source; pipes / sockets / timerfds / signalfds still
        // rely on the timer cadence within this loop.
        const bool has_pidfd = LinuxProcessHasPidfd(p);
        if (!infinite)
        {
            const u64 now = sched::SchedNowTicks();
            if (now >= deadline_tick)
                return 0;
            const u64 remaining = deadline_tick - now;
            const u64 step = (remaining < 1) ? 1 : ((remaining < 10) ? remaining : 10);
            if (has_pidfd)
                (void)sched::WaitQueueBlockTimeout(LinuxPidfdExitWq(), step);
            else
                sched::SchedSleepTicks(step);
        }
        else
        {
            if (has_pidfd)
                (void)sched::WaitQueueBlockTimeout(LinuxPidfdExitWq(), 10);
            else
                sched::SchedSleepTicks(10); // 100 ms infinite-poll cadence
        }
    }
}

i64 DoEpollPwait(u64 epfd, u64 events, u64 maxevents, u64 timeout_ms, u64 sigmask, u64 sigsetsize)
{
    (void)sigmask;
    (void)sigsetsize;
    return DoEpollWait(epfd, events, maxevents, timeout_ms);
}

// =============================================================
// epoll_pwait2 — same as epoll_pwait but the timeout is a
// `struct timespec*` (nsec precision) instead of an int (ms).
// =============================================================

// We round up to milliseconds — v0 has no nanosecond-grain
// scheduler tick anyway, so the loss is acceptable. NULL
// timeout = block forever (-1), zero timeout = poll once (0),
// positive timeout = ceil to ms.
i64 DoEpollPwait2(u64 epfd, u64 events, u64 maxevents, u64 user_ts, u64 sigmask, u64 sigsetsize)
{
    i64 timeout_ms = -1;
    if (user_ts != 0)
    {
        struct Timespec
        {
            i64 sec;
            i64 nsec;
        } ts = {};
        if (!mm::CopyFromUser(&ts, reinterpret_cast<const void*>(user_ts), sizeof(ts)))
            return kEFAULT;
        if (ts.sec == 0 && ts.nsec == 0)
            timeout_ms = 0;
        else
            timeout_ms = ts.sec * 1000 + (ts.nsec + 999999) / 1000000;
    }
    return DoEpollPwait(epfd, events, maxevents, static_cast<u64>(timeout_ms), sigmask, sigsetsize);
}

} // namespace duetos::subsystems::linux::internal
