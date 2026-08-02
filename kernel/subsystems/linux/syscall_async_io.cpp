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
 *              accumulated since the last read; blocks through a
 *              sequence-aware cancellable wait against the exact next
 *              deadline, so the timer-tick path itself needs no callback.
 *
 *   signalfd — slot stores the caller's mask. Reads drain matching
 *              bits from the process pending-signal bitmap into
 *              Linux-stable signalfd_siginfo records. Per-signal
 *              sender metadata is not tracked in v0, so those
 *              record fields remain zero.
 *
 *   epoll    — instance + dynamic watch table (16 slots / inst).
 *              epoll_wait polls every watched fd via the readiness
 *              helpers exposed by the pipe / eventfd / socket /
 *              timerfd surfaces, then parks on a shared publication
 *              sequence. Fd kinds without wake hooks retain the v0
 *              100 ms fallback cadence.
 *
 * CLOEXEC publication is atomic with fd installation. NONBLOCK is retained
 * in the shared open-file description and snapshotted before a read can park.
 */

#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "ipc/kfile.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

void LinuxPollEventWake();
u64 LinuxPollEventSequenceSnapshot();
const u64* LinuxPollEventSequenceAddress();
sched::WaitQueue* LinuxPollEventWq();

namespace
{

constexpr u32 kTimerfdPoolCap = 8;
constexpr u32 kSignalfdPoolCap = 8;
constexpr u32 kEpollPoolCap = 8;
constexpr u32 kEpollWatchCap = 16;
constexpr u32 kLinuxFdCap = 16;

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
    bool closing;
    u8 _pad[2];
    u32 refs;
    u32 pins;
    u64 next_expiry_tick; // SchedNowTicks() target; 0 = disarmed
    u64 interval_ticks;   // 0 = one-shot
    u64 expirations;      // accumulated since last read
    u32 clock_id;
    u32 _pad2;
    u64 generation;
    u64 read_sequence;
    sched::WaitQueue read_wq;
};

struct Signalfd
{
    bool in_use;
    bool closing;
    u8 _pad[2];
    u32 refs;
    u32 pins;
    u64 mask;
    u64 generation;
};

struct EpollWatch
{
    bool in_use;
    u8 _pad[3];
    u32 source_fd;
    u32 events; // EPOLLIN / EPOLLOUT / EPOLLERR / EPOLLHUP
    u32 _pad2;
    u64 user_data; // epoll_event.data — opaque to us
    core::LinuxFdAcquired acquired;
};

struct Epoll
{
    bool in_use;
    bool closing;
    u8 _pad[2];
    u32 refs;
    u32 pins;
    u32 watch_count;
    u32 _pad2;
    u64 generation;
    EpollWatch watches[kEpollWatchCap];
};

bool EpollWatchMatchesIdentity(const EpollWatch& watch, u32 source_fd, const core::LinuxFdAcquired& candidate)
{
    return watch.in_use && watch.source_fd == source_fd &&
           watch.acquired.snapshot.generation == candidate.snapshot.generation &&
           watch.acquired.snapshot.state == candidate.snapshot.state &&
           watch.acquired.snapshot.first_cluster == candidate.snapshot.first_cluster &&
           watch.acquired.snapshot.ofd == candidate.snapshot.ofd && watch.acquired.kfile_ref == candidate.kfile_ref;
}

Timerfd g_timerfd_pool[kTimerfdPoolCap];
Signalfd g_signalfd_pool[kSignalfdPoolCap];
Epoll g_epoll_pool[kEpollPoolCap];
constinit sync::SpinLock g_async_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

void AdvanceStableSequenceLocked(u64* sequence)
{
    const u64 previous = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    if (previous != ~u64{0})
        __atomic_store_n(sequence, previous + 1, __ATOMIC_RELEASE);
}

void WakeQueuePreservingInterrupts(sched::WaitQueue* queue)
{
    constexpr u64 kRflagsInterruptEnable = 1ULL << 9;
    const bool interrupts_were_enabled = (arch::ReadRflags() & kRflagsInterruptEnable) != 0;
    arch::Cli();
    sched::WaitQueueWakeAll(queue);
    if (interrupts_were_enabled)
        arch::Sti();
}

sched::WaitQueueBlockResult WaitForStableSequence(sched::WaitQueue* queue, const u64* sequence, u64 observed_sequence)
{
    if (observed_sequence == ~u64{0})
        return sched::WaitQueueBlockTimeoutCancellable(queue, 1);
    return sched::WaitQueueBlockIfSequenceUnchangedCancellable(queue, sequence, observed_sequence);
}

sched::WaitQueueBlockResult WaitForStableSequenceTimeout(sched::WaitQueue* queue, const u64* sequence,
                                                         u64 observed_sequence, u64 ticks)
{
    if (observed_sequence == ~u64{0})
        return sched::WaitQueueBlockTimeoutCancellable(queue, ticks > 1 ? 1 : ticks);
    return sched::WaitQueueBlockIfSequenceUnchangedTimeoutCancellable(queue, sequence, observed_sequence, ticks);
}

struct TimerfdPin
{
    u32 idx;
    u64 generation;
    Timerfd* timer;

    explicit TimerfdPin(u32 value, u64 expected_generation = 0) : idx(value), generation(0), timer(nullptr)
    {
        if (value >= kTimerfdPoolCap)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Timerfd& t = g_timerfd_pool[value];
        if (t.in_use && !t.closing && t.pins != ~0U &&
            (expected_generation == 0 || t.generation == expected_generation))
        {
            ++t.pins;
            generation = t.generation;
            timer = &t;
        }
    }

    ~TimerfdPin() { Release(); }

    void Release()
    {
        if (timer == nullptr)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Timerfd& t = g_timerfd_pool[idx];
        if (t.pins > 0)
            --t.pins;
        if (t.pins == 0 && t.refs == 0)
        {
            t.in_use = false;
            t.closing = false;
            t.next_expiry_tick = 0;
            t.interval_ticks = 0;
            t.expirations = 0;
        }
        generation = 0;
        timer = nullptr;
    }

    explicit operator bool() const { return timer != nullptr; }
};

struct EpollPin
{
    u32 idx;
    u64 generation;
    Epoll* epoll;

    explicit EpollPin(u32 value, u64 expected_generation = 0) : idx(value), generation(0), epoll(nullptr)
    {
        if (value >= kEpollPoolCap)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Epoll& e = g_epoll_pool[value];
        if (e.in_use && !e.closing && e.pins != ~0U &&
            (expected_generation == 0 || e.generation == expected_generation))
        {
            ++e.pins;
            generation = e.generation;
            epoll = &e;
        }
    }

    ~EpollPin() { Release(); }

    void Release()
    {
        if (epoll == nullptr)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Epoll& e = g_epoll_pool[idx];
        if (e.pins > 0)
            --e.pins;
        if (e.pins == 0 && e.refs == 0)
        {
            e.in_use = false;
            e.closing = false;
            e.watch_count = 0;
        }
        generation = 0;
        epoll = nullptr;
    }

    explicit operator bool() const { return epoll != nullptr; }
};

struct ScopedLinuxFdAcquired
{
    core::LinuxFdAcquired* acquired;

    explicit ScopedLinuxFdAcquired(core::LinuxFdAcquired* value) : acquired(value) {}
    ~ScopedLinuxFdAcquired()
    {
        if (acquired != nullptr)
            core::LinuxFdAcquiredRelease(acquired);
    }

    ScopedLinuxFdAcquired(const ScopedLinuxFdAcquired&) = delete;
    ScopedLinuxFdAcquired& operator=(const ScopedLinuxFdAcquired&) = delete;
};

struct SignalfdPin
{
    u32 idx;
    u64 generation;
    Signalfd* signalfd;

    explicit SignalfdPin(u32 value, u64 expected_generation = 0) : idx(value), generation(0), signalfd(nullptr)
    {
        if (value >= kSignalfdPoolCap)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Signalfd& s = g_signalfd_pool[value];
        if (s.in_use && !s.closing && s.pins != ~0U &&
            (expected_generation == 0 || s.generation == expected_generation))
        {
            ++s.pins;
            generation = s.generation;
            signalfd = &s;
        }
    }

    ~SignalfdPin() { Release(); }

    void Release()
    {
        if (signalfd == nullptr)
            return;
        sync::SpinLockGuard guard(g_async_lock);
        Signalfd& s = g_signalfd_pool[idx];
        if (s.pins > 0)
            --s.pins;
        if (s.pins == 0 && s.refs == 0)
        {
            s.in_use = false;
            s.closing = false;
            s.mask = 0;
        }
        generation = 0;
        signalfd = nullptr;
    }

    explicit operator bool() const { return signalfd != nullptr; }
};

i32 TimerfdAlloc(u32 clock_id)
{
    sync::SpinLockGuard guard(g_async_lock);
    for (u32 i = 0; i < kTimerfdPoolCap; ++i)
    {
        if (!g_timerfd_pool[i].in_use && g_timerfd_pool[i].generation != ~u64{0})
        {
            Timerfd& t = g_timerfd_pool[i];
            ++t.generation;
            AdvanceStableSequenceLocked(&t.read_sequence);
            t.in_use = true;
            t.closing = false;
            t.refs = 1;
            t.pins = 0;
            t.next_expiry_tick = 0;
            t.interval_ticks = 0;
            t.expirations = 0;
            t.clock_id = clock_id;
            return static_cast<i32>(i);
        }
    }
    return -1;
}

i32 SignalfdAlloc(u64 mask)
{
    sync::SpinLockGuard guard(g_async_lock);
    for (u32 i = 0; i < kSignalfdPoolCap; ++i)
    {
        if (!g_signalfd_pool[i].in_use && g_signalfd_pool[i].generation != ~u64{0})
        {
            Signalfd& s = g_signalfd_pool[i];
            ++s.generation;
            s.in_use = true;
            s.closing = false;
            s.refs = 1;
            s.pins = 0;
            s.mask = mask;
            return static_cast<i32>(i);
        }
    }
    return -1;
}

i32 EpollAlloc()
{
    sync::SpinLockGuard guard(g_async_lock);
    for (u32 i = 0; i < kEpollPoolCap; ++i)
    {
        if (!g_epoll_pool[i].in_use && g_epoll_pool[i].generation != ~u64{0})
        {
            Epoll& e = g_epoll_pool[i];
            ++e.generation;
            e.in_use = true;
            e.closing = false;
            e.refs = 1;
            e.pins = 0;
            e.watch_count = 0;
            for (u32 w = 0; w < kEpollWatchCap; ++w)
                e.watches[w] = {};
            return static_cast<i32>(i);
        }
    }
    return -1;
}

// Catch up `expirations` based on the current tick. Caller must hold
// g_async_lock on entry.
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

void TimerfdRelease(u32 idx)
{
    if (idx >= kTimerfdPoolCap)
        return;
    bool wake = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_async_lock);
    Timerfd& t = g_timerfd_pool[idx];
    if (!t.in_use || t.refs == 0)
    {
        sync::SpinLockRelease(g_async_lock, flags);
        return;
    }
    --t.refs;
    if (t.refs == 0)
    {
        t.closing = true;
        AdvanceStableSequenceLocked(&t.read_sequence);
        wake = true;
        if (t.pins == 0)
        {
            t.in_use = false;
            t.closing = false;
            t.next_expiry_tick = 0;
            t.interval_ticks = 0;
            t.expirations = 0;
        }
    }
    sync::SpinLockRelease(g_async_lock, flags);
    if (wake)
    {
        WakeQueuePreservingInterrupts(&t.read_wq);
        LinuxPollEventWake();
    }
}

i64 TimerfdRead(u32 idx, u64 user_dst, u64 len, bool nonblocking)
{
    if (idx >= kTimerfdPoolCap)
        return kEINVAL;
    if (len < 8)
        return kEINVAL; // timerfd reads are u64-sized
    u64 expected_generation = 0;
    while (true)
    {
        TimerfdPin pin(idx, expected_generation);
        if (!pin)
            return 0;
        if (expected_generation == 0)
            expected_generation = pin.generation;
        auto flags = sync::SpinLockAcquire(g_async_lock);
        Timerfd& t = *pin.timer;
        if (!t.in_use || t.closing || t.generation != expected_generation)
        {
            sync::SpinLockRelease(g_async_lock, flags);
            return 0;
        }
        const u64 observed_sequence = __atomic_load_n(&t.read_sequence, __ATOMIC_ACQUIRE);
        TimerfdAccrueExpirationsLocked(t, sched::SchedNowTicks());
        if (t.expirations > 0)
        {
            const u64 expirations = t.expirations;
            t.expirations = 0;
            sync::SpinLockRelease(g_async_lock, flags);
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), &expirations, sizeof(expirations)))
                return kEFAULT;
            return 8;
        }
        if (nonblocking)
        {
            sync::SpinLockRelease(g_async_lock, flags);
            return kEAGAIN;
        }
        if (t.next_expiry_tick == 0)
        {
            // Disarmed and no expirations — block until armed/closed.
            sync::SpinLockRelease(g_async_lock, flags);
            pin.Release();
            if (WaitForStableSequence(&t.read_wq, &t.read_sequence, observed_sequence) ==
                sched::WaitQueueBlockResult::Cancelled)
            {
                return kEINTR;
            }
            continue;
        }
        const u64 now = sched::SchedNowTicks();
        const u64 wait = (t.next_expiry_tick > now) ? (t.next_expiry_tick - now) : 1;
        sync::SpinLockRelease(g_async_lock, flags);
        pin.Release();
        if (WaitForStableSequenceTimeout(&t.read_wq, &t.read_sequence, observed_sequence, wait) ==
            sched::WaitQueueBlockResult::Cancelled)
        {
            return kEINTR;
        }
    }
}

i64 DoTimerfdCreate(u64 clockid, u64 flags)
{
    constexpr u64 kTFD_CLOEXEC = 0x80000;
    constexpr u64 kTFD_NONBLOCK = 0x800;
    if ((flags & ~(kTFD_CLOEXEC | kTFD_NONBLOCK)) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 idx = TimerfdAlloc(static_cast<u32>(clockid));
    if (idx < 0)
        return kENFILE;

    auto kfile_result = ipc::KFileCreate(ipc::KFileKind::Timerfd, static_cast<u32>(idx), &TimerfdRelease, nullptr, 0);
    if (!kfile_result.has_value())
    {
        TimerfdRelease(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd payload{};
    payload.state = 7;
    payload.first_cluster = static_cast<u32>(idx);
    core::LinuxFdPrepared prepared{};
    constexpr u32 kO_RDWR = 2;
    const u32 status_flags = kO_RDWR | static_cast<u32>(flags & kTFD_NONBLOCK);
    if (!core::LinuxFdPrepare(&prepared, payload, &kfile_result.value()->base, status_flags))
    {
        ipc::KObjectRelease(&kfile_result.value()->base);
        return kENFILE;
    }
    const i32 fd = core::LinuxFdBindLowest(p, 3, &prepared, (flags & kTFD_CLOEXEC) != 0);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
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
    constexpr u64 kMax = static_cast<u64>(-1);
    const u64 sec_u = static_cast<u64>(sec);
    const u64 nsec_u = static_cast<u64>(nsec);
    if (sec_u > (kMax - nsec_u) / 1'000'000'000ull)
        return kMax / kTickNs;
    const u64 total_ns = sec_u * 1'000'000'000ull + nsec_u;
    if (total_ns == 0)
        return 0;
    return total_ns > kMax - (kTickNs - 1) ? kMax / kTickNs : (total_ns + kTickNs - 1) / kTickNs;
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
    if (p == nullptr || fd >= kLinuxFdCap)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, kLinuxFdCap);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 7, &acquired))
        return kEBADF;
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kTimerfdPoolCap)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    TimerfdPin pin(idx);
    if (!pin)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    Itimerspec new_spec{};
    if (!mm::CopyFromUser(&new_spec, reinterpret_cast<const void*>(user_new), sizeof(new_spec)))
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEFAULT;
    }
    if (new_spec.it_value_sec < 0 || new_spec.it_interval_sec < 0 || new_spec.it_value_nsec < 0 ||
        new_spec.it_interval_nsec < 0 || new_spec.it_value_nsec >= 1'000'000'000 ||
        new_spec.it_interval_nsec >= 1'000'000'000)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    const u64 first_ticks = ItimerspecToTicks(new_spec.it_value_sec, new_spec.it_value_nsec);
    const u64 interval_ticks = ItimerspecToTicks(new_spec.it_interval_sec, new_spec.it_interval_nsec);
    constexpr u64 kTfdTimerAbstime = 0x1;
    if ((flags & ~kTfdTimerAbstime) != 0)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    Itimerspec old_spec{};
    const auto lock_flags = sync::SpinLockAcquire(g_async_lock);
    Timerfd& t = *pin.timer;
    if (!t.in_use || t.closing)
    {
        sync::SpinLockRelease(g_async_lock, lock_flags);
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    const u64 now = sched::SchedNowTicks();
    if (t.next_expiry_tick > now)
        TicksToItimerspec(t.next_expiry_tick - now, old_spec.it_value_sec, old_spec.it_value_nsec);
    TicksToItimerspec(t.interval_ticks, old_spec.it_interval_sec, old_spec.it_interval_nsec);
    if (first_ticks == 0)
    {
        // Disarm.
        t.next_expiry_tick = 0;
        t.interval_ticks = 0;
    }
    else
    {
        if ((flags & kTfdTimerAbstime) != 0)
            t.next_expiry_tick = first_ticks; // absolute tick value (caller-side).
        else
            t.next_expiry_tick = first_ticks > static_cast<u64>(-1) - now ? static_cast<u64>(-1) : now + first_ticks;
        t.interval_ticks = interval_ticks;
    }
    t.expirations = 0;
    AdvanceStableSequenceLocked(&t.read_sequence);
    sync::SpinLockRelease(g_async_lock, lock_flags);
    WakeQueuePreservingInterrupts(&t.read_wq);
    LinuxPollEventWake();
    if (user_old != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_old), &old_spec, sizeof(old_spec)))
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEFAULT;
    }
    core::LinuxFdAcquiredRelease(&acquired);
    return 0;
}

i64 DoTimerfdGettime(u64 fd, u64 user_curr)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= kLinuxFdCap)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, kLinuxFdCap);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 7, &acquired))
        return kEBADF;
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kTimerfdPoolCap)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    TimerfdPin pin(idx);
    if (!pin)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    Itimerspec out{};
    auto lock_flags = sync::SpinLockAcquire(g_async_lock);
    Timerfd& t = *pin.timer;
    if (!t.in_use || t.closing)
    {
        sync::SpinLockRelease(g_async_lock, lock_flags);
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    const u64 now = sched::SchedNowTicks();
    if (t.next_expiry_tick > now)
        TicksToItimerspec(t.next_expiry_tick - now, out.it_value_sec, out.it_value_nsec);
    TicksToItimerspec(t.interval_ticks, out.it_interval_sec, out.it_interval_nsec);
    sync::SpinLockRelease(g_async_lock, lock_flags);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_curr), &out, sizeof(out)))
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEFAULT;
    }
    core::LinuxFdAcquiredRelease(&acquired);
    return 0;
}

// ============================================================
// Signalfd
// ============================================================

void SignalfdRelease(u32 idx)
{
    if (idx >= kSignalfdPoolCap)
        return;
    sync::SpinLockGuard guard(g_async_lock);
    Signalfd& s = g_signalfd_pool[idx];
    if (!s.in_use || s.refs == 0)
    {
        return;
    }
    --s.refs;
    if (s.refs == 0)
    {
        s.closing = true;
        if (s.pins == 0)
        {
            s.in_use = false;
            s.closing = false;
            s.mask = 0;
        }
    }
}

i64 SignalfdRead(u32 idx, u64 user_dst, u64 len, bool nonblocking)
{
    if (idx >= kSignalfdPoolCap)
        return kEINVAL;
    if (len < 128) // sizeof(struct signalfd_siginfo)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;
    u64 expected_generation = 0;
    while (true)
    {
        const u64 observed_sequence = core::ProcessLinuxSignalEventSequenceSnapshot(p);
        SignalfdPin pin(idx, expected_generation);
        if (!pin)
            return 0;
        if (expected_generation == 0)
            expected_generation = pin.generation;
        auto lock_flags = sync::SpinLockAcquire(g_async_lock);
        Signalfd& s = *pin.signalfd;
        if (!s.in_use || s.closing || s.generation != expected_generation)
        {
            sync::SpinLockRelease(g_async_lock, lock_flags);
            return 0;
        }
        // Walk the pending bitmap; emit one signalfd_siginfo per
        // matching signum, clear the bit. Caller-supplied buffer
        // determines how many we can emit (each record = 128 bytes).
        u8 stage[256];
        u64 emitted = 0;
        u64 claimed_mask = 0;
        for (u32 sig = 1;
             sig < core::Process::kLinuxSignalCount && emitted + 128 <= len && emitted + 128 <= sizeof(stage); ++sig)
        {
            const u64 bit = core::ProcessLinuxSignalBit(sig);
            if ((s.mask & bit) == 0)
                continue;
            // Claim the exact coalesced signal bit. A producer on another CPU may
            // publish concurrently; compare/exchange prevents this consumer from
            // erasing that publication through a stale load/store pair.
            if (!core::ProcessLinuxSignalClaimPending(p, sig))
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
            claimed_mask |= bit;
            emitted += 128;
        }
        sync::SpinLockRelease(g_async_lock, lock_flags);
        if (emitted == 0)
        {
            if (nonblocking)
                return kEAGAIN;
            pin.Release();
            if (core::ProcessWaitForLinuxSignalEvent(p, observed_sequence) == sched::WaitQueueBlockResult::Cancelled)
            {
                return kEINTR;
            }
            continue;
        }
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, emitted))
        {
            // read(2) may consume only after its output is committed. Re-publish
            // every claimed bit on EFAULT; standard signals remain coalesced if a
            // producer raised the same signum during the copy attempt.
            core::ProcessLinuxSignalRestorePending(p, claimed_mask);
            return kEFAULT;
        }
        return static_cast<i64>(emitted);
    }
}

i64 DoSignalfd(u64 fd, u64 user_mask, u64 sigsetsize, u64 flags)
{
    constexpr u64 kSFD_CLOEXEC = 0x80000;
    constexpr u64 kSFD_NONBLOCK = 0x800;
    if ((flags & ~(kSFD_CLOEXEC | kSFD_NONBLOCK)) != 0)
        return kEINVAL;
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
        if (fd >= kLinuxFdCap)
            return kEINVAL;
        // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
        fd = util::MaskedIndex(fd, kLinuxFdCap);
        core::LinuxFdAcquired acquired{};
        if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 8, &acquired))
            return kEINVAL;
        const u32 idx = acquired.snapshot.first_cluster;
        if (idx >= kSignalfdPoolCap)
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEINVAL;
        }
        SignalfdPin pin(idx);
        if (!pin)
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEINVAL;
        }
        bool updated = false;
        {
            sync::SpinLockGuard guard(g_async_lock);
            if (pin.signalfd->in_use && !pin.signalfd->closing)
            {
                pin.signalfd->mask = mask;
                updated = true;
            }
        }
        core::LinuxFdAcquiredRelease(&acquired);
        if (updated)
        {
            core::ProcessLinuxSignalNotifyWaiters(p);
            LinuxPollEventWake();
        }
        return updated ? static_cast<i64>(fd) : kEINVAL;
    }
    const i32 idx = SignalfdAlloc(mask);
    if (idx < 0)
        return kENFILE;

    auto kfile_result = ipc::KFileCreate(ipc::KFileKind::Signalfd, static_cast<u32>(idx), &SignalfdRelease, nullptr, 0);
    if (!kfile_result.has_value())
    {
        SignalfdRelease(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd payload{};
    payload.state = 8;
    payload.first_cluster = static_cast<u32>(idx);
    core::LinuxFdPrepared prepared{};
    constexpr u32 kO_RDWR = 2;
    const u32 status_flags = kO_RDWR | static_cast<u32>(flags & kSFD_NONBLOCK);
    if (!core::LinuxFdPrepare(&prepared, payload, &kfile_result.value()->base, status_flags))
    {
        ipc::KObjectRelease(&kfile_result.value()->base);
        return kENFILE;
    }
    const i32 new_fd = core::LinuxFdBindLowest(p, 3, &prepared, (flags & kSFD_CLOEXEC) != 0);
    if (new_fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
    arch::SerialWrite("[linux/signalfd] fd=");
    arch::SerialWriteHex(static_cast<u64>(new_fd));
    arch::SerialWrite(" mask=");
    arch::SerialWriteHex(mask);
    arch::SerialWrite("\n");
    return static_cast<i64>(new_fd);
}

// ============================================================
// Epoll
// ============================================================

void EpollRelease(u32 idx)
{
    if (idx >= kEpollPoolCap)
        return;

    core::LinuxFdAcquired detached[kEpollWatchCap]{};
    u32 detached_count = 0;
    bool published_close = false;
    {
        sync::SpinLockGuard guard(g_async_lock);
        Epoll& e = g_epoll_pool[idx];
        if (e.in_use && e.refs > 0)
        {
            --e.refs;
            if (e.refs == 0)
            {
                e.closing = true;
                published_close = true;
                for (u32 w = 0; w < kEpollWatchCap; ++w)
                {
                    EpollWatch& watch = e.watches[w];
                    if (!watch.in_use)
                        continue;
                    detached[detached_count++] = watch.acquired;
                    watch = {};
                }
                e.watch_count = 0;
                if (e.pins == 0)
                {
                    e.in_use = false;
                    e.closing = false;
                }
            }
        }
    }

    for (u32 i = 0; i < detached_count; ++i)
        core::LinuxFdAcquiredRelease(&detached[i]);
    if (published_close)
        LinuxPollEventWake();
}

u32 LinuxFdEpollReady(const core::LinuxFdAcquired& acquired, u32 interest_mask, core::Process* signal_owner)
{
    const auto& slot = acquired.snapshot;
    if (acquired.snapshot.state == 0)
        return kEPOLLERR | kEPOLLHUP;
    u32 ready = 0;
    switch (acquired.snapshot.state)
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
            TimerfdPin pin(slot.first_cluster);
            if (pin)
            {
                sync::SpinLockGuard guard(g_async_lock);
                Timerfd& t = *pin.timer;
                TimerfdAccrueExpirationsLocked(t, sched::SchedNowTicks());
                if (t.expirations > 0)
                    ready |= kEPOLLIN;
            }
        }
        break;
    }
    case 8: // signalfd
    {
        if ((interest_mask & kEPOLLIN) != 0 && signal_owner != nullptr)
        {
            SignalfdPin pin(slot.first_cluster);
            if (pin)
            {
                sync::SpinLockGuard guard(g_async_lock);
                const Signalfd& signal = *pin.signalfd;
                if (signal.in_use && !signal.closing &&
                    (core::ProcessLinuxSignalPendingSnapshot(signal_owner) & signal.mask) != 0)
                    ready |= kEPOLLIN;
            }
        }
        break;
    }
    case 9: // epoll instance — never readable through epoll
        break;
    case 12: // pidfd — readable iff target process has exited
        if (interest_mask & kEPOLLIN)
        {
            // Resolve the exact KFile-owned identity. A missing/stale/corrupt
            // target is an invalid watched descriptor, not evidence that some
            // numeric PID exited. Readiness begins only after runtime teardown
            // release-publishes the stable inert Exited header.
            if (acquired.kfile_ref == nullptr)
                break;
            core::ScopedProcessRef target(LinuxPidfdAcquireTarget(acquired));
            if (target && core::ProcessLifecycleLoad(target.Get()) == core::ProcessLifecycleState::Exited)
                ready |= kEPOLLIN;
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
    constexpr u64 kEPOLL_CLOEXEC = 0x80000;
    if ((flags & ~kEPOLL_CLOEXEC) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 idx = EpollAlloc();
    if (idx < 0)
        return kENFILE;

    auto file_result = ipc::KFileCreate(ipc::KFileKind::Epoll, static_cast<u32>(idx), &EpollRelease, nullptr, 0);
    if (!file_result.has_value())
    {
        EpollRelease(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd payload{};
    payload.state = 9;
    payload.first_cluster = static_cast<u32>(idx);
    payload.kf_handle = ipc::kHandleInvalid;
    core::LinuxFdPrepared prepared{};
    if (!core::LinuxFdPrepare(&prepared, payload, &file_result.value()->base, 0))
    {
        ipc::KObjectRelease(&file_result.value()->base);
        return kENOMEM;
    }
    const i32 fd = core::LinuxFdBindLowest(p, 3, &prepared, (flags & kEPOLL_CLOEXEC) != 0);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
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
    if (p == nullptr || epfd >= kLinuxFdCap || fd >= kLinuxFdCap)
        return kEBADF;
    if (op != kEpollCtlAdd && op != kEpollCtlDel && op != kEpollCtlMod)
        return kEINVAL;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    epfd = util::MaskedIndex(epfd, kLinuxFdCap);
    fd = util::MaskedIndex(fd, kLinuxFdCap);

    core::LinuxFdAcquired epoll_acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(epfd), 9, &epoll_acquired))
        return kEBADF;
    const u32 idx = epoll_acquired.snapshot.first_cluster;
    if (idx >= kEpollPoolCap)
    {
        core::LinuxFdAcquiredRelease(&epoll_acquired);
        return kEINVAL;
    }
    EpollPin pin(idx);
    core::LinuxFdAcquiredRelease(&epoll_acquired);
    if (!pin)
        return kEBADF;

    core::LinuxFdAcquired candidate{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &candidate))
        return kEBADF;
    // v0 has no nested-epoll cycle detector. Reject epoll sources instead of
    // creating an uncollectable KFile reference cycle.
    if (candidate.snapshot.state == 9)
    {
        core::LinuxFdAcquiredRelease(&candidate);
        return kEINVAL;
    }

    EpollEvent ev{};
    if (op != kEpollCtlDel)
    {
        if (user_event == 0 || !mm::CopyFromUser(&ev, reinterpret_cast<const void*>(user_event), sizeof(ev)))
        {
            core::LinuxFdAcquiredRelease(&candidate);
            return kEFAULT;
        }
    }

    core::LinuxFdAcquired detached{};
    i64 result = kEINVAL;
    {
        sync::SpinLockGuard guard(g_async_lock);
        Epoll& e = *pin.epoll;
        if (!e.in_use || e.closing)
        {
            result = kEBADF;
        }
        else
        {
            i32 found = -1;
            for (u32 w = 0; w < kEpollWatchCap; ++w)
            {
                const EpollWatch& watch = e.watches[w];
                if (EpollWatchMatchesIdentity(watch, static_cast<u32>(fd), candidate))
                {
                    found = static_cast<i32>(w);
                    break;
                }
            }

            if (op == kEpollCtlAdd)
            {
                result = -17; // -EEXIST
                if (found < 0)
                {
                    result = kENOMEM;
                    for (u32 w = 0; w < kEpollWatchCap; ++w)
                    {
                        if (e.watches[w].in_use)
                            continue;
                        EpollWatch& watch = e.watches[w];
                        watch.in_use = true;
                        watch.source_fd = static_cast<u32>(fd);
                        watch.events = ev.events;
                        watch.user_data = ev.data;
                        watch.acquired = candidate;
                        candidate = {};
                        ++e.watch_count;
                        result = 0;
                        break;
                    }
                }
            }
            else if (op == kEpollCtlDel)
            {
                result = kENOENT;
                if (found >= 0)
                {
                    EpollWatch& watch = e.watches[static_cast<u32>(found)];
                    detached = watch.acquired;
                    watch = {};
                    --e.watch_count;
                    result = 0;
                }
            }
            else
            {
                result = kENOENT;
                if (found >= 0)
                {
                    EpollWatch& watch = e.watches[static_cast<u32>(found)];
                    watch.events = ev.events;
                    watch.user_data = ev.data;
                    result = 0;
                }
            }
        }
    }

    core::LinuxFdAcquiredRelease(&candidate);
    core::LinuxFdAcquiredRelease(&detached);
    if (result == 0)
        LinuxPollEventWake();
    return result;
}

i64 DoEpollWait(u64 epfd, u64 user_events, u64 maxevents, u64 timeout_ms)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || epfd >= kLinuxFdCap)
        return kEBADF;
    epfd = util::MaskedIndex(epfd, kLinuxFdCap);
    if (maxevents == 0)
        return kEINVAL;
    if (maxevents > 64)
        maxevents = 64;

    core::LinuxFdAcquired epoll_acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(epfd), 9, &epoll_acquired))
        return kEBADF;
    ScopedLinuxFdAcquired epoll_receipt(&epoll_acquired);
    const u32 idx = epoll_acquired.snapshot.first_cluster;
    if (idx >= kEpollPoolCap)
        return kEINVAL;
    // Convert timeout_ms (signed by caller convention; -1 = infinite)
    // into a tick budget. 10 ms per tick, round up so a 1 ms timeout
    // still polls once before returning.
    bool infinite = false;
    u64 deadline_tick = 0;
    constexpr u64 kInfiniteTimeout = static_cast<u64>(-1);
    constexpr u64 kMaxSignedTimeout = 0x7FFF'FFFF'FFFF'FFFFull;
    if (timeout_ms == kInfiniteTimeout)
        infinite = true;
    else if (timeout_ms > kMaxSignedTimeout)
        return kEINVAL;
    else
    {
        const u64 ticks = timeout_ms / 10 + ((timeout_ms % 10) != 0 ? 1 : 0);
        const u64 now = sched::SchedNowTicks();
        deadline_tick = (ticks > static_cast<u64>(-1) - now) ? static_cast<u64>(-1) : now + ticks;
    }
    EpollEvent out_buf[64];
    u64 expected_generation = 0;
    while (true)
    {
        // Snapshot before evaluating readiness. Any publisher that races the
        // scan either changes this value before enqueue or wakes the enqueued
        // waiter afterwards.
        const u64 observed_poll_sequence = LinuxPollEventSequenceSnapshot();
        EpollPin pin(idx, expected_generation);
        if (!pin)
            return kEBADF;
        if (expected_generation == 0)
            expected_generation = pin.generation;

        u32 hits = 0;
        bool snapshot_ok = true;
        EpollWatch snap[kEpollWatchCap]{};
        auto lock_flags = sync::SpinLockAcquire(g_async_lock);
        Epoll& e = *pin.epoll;
        if (!e.in_use || e.closing || e.generation != expected_generation)
        {
            sync::SpinLockRelease(g_async_lock, lock_flags);
            return kEBADF;
        }
        for (u32 w = 0; w < kEpollWatchCap; ++w)
        {
            const EpollWatch& watch = e.watches[w];
            if (!watch.in_use)
                continue;
            snap[w].in_use = true;
            snap[w].source_fd = watch.source_fd;
            snap[w].events = watch.events;
            snap[w].user_data = watch.user_data;
            if (!core::LinuxFdAcquiredClone(&watch.acquired, &snap[w].acquired))
            {
                snapshot_ok = false;
                break;
            }
        }
        sync::SpinLockRelease(g_async_lock, lock_flags);
        // The retained fd receipt anchors this exact epoll instance. A pool pin
        // is needed only while cloning its watch table and must never cross a
        // readiness callback or scheduler block.
        pin.Release();

        if (snapshot_ok)
        {
            for (u32 w = 0; w < kEpollWatchCap; ++w)
            {
                if (!snap[w].in_use)
                    continue;
                if (hits < maxevents)
                {
                    const u32 ready = LinuxFdEpollReady(snap[w].acquired, snap[w].events, p);
                    if (ready != 0)
                    {
                        out_buf[hits].events = ready;
                        out_buf[hits].data = snap[w].user_data;
                        ++hits;
                    }
                }
            }
        }

        for (u32 w = 0; w < kEpollWatchCap; ++w)
            core::LinuxFdAcquiredRelease(&snap[w].acquired);
        if (!snapshot_ok)
            return kEBADF;

        if (hits > 0)
        {
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_events), out_buf, hits * sizeof(EpollEvent)))
                return kEFAULT;
            return static_cast<i64>(hits);
        }
        u64 step = 10; // Preserve the v0 100 ms fallback for fd kinds without hooks.
        if (!infinite)
        {
            const u64 now = sched::SchedNowTicks();
            if (now >= deadline_tick)
                return 0;
            const u64 remaining = deadline_tick - now;
            step = remaining < 10 ? remaining : 10;
        }
        const sched::WaitQueueBlockResult wait_result = WaitForStableSequenceTimeout(
            LinuxPollEventWq(), LinuxPollEventSequenceAddress(), observed_poll_sequence, step);
        if (wait_result == sched::WaitQueueBlockResult::Cancelled)
        {
            return kEINTR;
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
        if (ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1000000000LL)
            return kEINVAL;
        if (ts.sec == 0 && ts.nsec == 0)
            timeout_ms = 0;
        else
        {
            constexpr i64 kMaxTimeoutMs = 0x7fff'ffff'ffff'ffffLL;
            const i64 rounded_ms = (ts.nsec + 999999) / 1000000;
            if (ts.sec > (kMaxTimeoutMs - rounded_ms) / 1000)
                timeout_ms = kMaxTimeoutMs;
            else
                timeout_ms = ts.sec * 1000 + rounded_ms;
        }
    }
    return DoEpollPwait(epfd, events, maxevents, static_cast<u64>(timeout_ms), sigmask, sigsetsize);
}

} // namespace duetos::subsystems::linux::internal
