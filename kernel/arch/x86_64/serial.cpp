#include "arch/x86_64/serial.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "cpu/percpu.h"
#include "sync/spinlock.h"

namespace duetos::arch
{

namespace
{

/* 16550 register offsets from the base port. */
constexpr u16 kRegData = 0;         // DLAB=0: RBR/THR
constexpr u16 kRegInterruptEn = 1;  // DLAB=0: IER
constexpr u16 kRegFifoControl = 2;  // FCR (write-only)
constexpr u16 kRegLineControl = 3;  // LCR
constexpr u16 kRegModemControl = 4; // MCR
constexpr u16 kRegLineStatus = 5;   // LSR

constexpr u8 kLsrDataReady = 1u << 0;
constexpr u8 kLsrTransmitEmpty = 1u << 5;
constexpr u8 kLcrDlab = 1u << 7;
constexpr u8 kLcr8N1 = 0b00000011;

// Per-port lock. SpinLockAcquire saves+disables IRQs so no IRQ
// handler can preempt a SerialWrite on this CPU and self-deadlock.
// Cross-CPU contention falls through to busy-wait.
duetos::sync::SpinLock g_serial_lock{};

// Set by SerialEnterPanicMode; checked at every Write* entry. Once
// flipped, every subsequent Write* skips the lock entirely. The kernel
// halts before clearing it. Volatile because we read it from arbitrary
// contexts (NMI handler may race with the setter on another CPU).
volatile u32 g_serial_panic_mode = 0;

// Re-entry guard. The serial spinlock disables IRQs on acquire, but
// TRAPS (#PF, #GP, NMI, #DB, ...) still fire while it's held. If the
// trap handler logs anything via SerialWrite, the recursive
// SpinLockAcquire would spin forever waiting for itself. To avoid
// that, every Write* entry checks this flag first; if set, it bypasses
// the lock and writes the bytes raw. The set must happen BEFORE the
// SpinLockAcquire call so a trap that fires mid-acquire still sees
// the flag set and bypasses cleanly.
//
// PER-CPU (2026-05-22). The original shape was a single global
// volatile u32 with the comment "graduates to a per-CPU array
// when multi-CPU boots land." That moment came and the comment
// got stale: CPU A's SerialWrite would set the flag to 1, take
// `g_serial_lock`, and start writing bytes. CPU B's SerialWrite
// would observe `g_serial_in_progress=1` from A and take the
// bypass path — emitting RAW bytes (no lock!) that interleaved
// with A's lock-protected bytes at the UART. Observed 2026-05-22
// on `tools/test/smp-stress-sweep.sh 8 8 5` (SMP=8 release) as
// 3-of-5 repeats showing torn `[stress] pre  heap_used_KiB=` lines
// with interleaved `flight (last X)` syscall-trail entries from a
// peer's proc-release diagnostic. Per-CPU storage closes the
// cross-CPU bypass: each CPU's slot is touched only by that CPU
// (cli during the critical section keeps IRQs out), and a peer
// CPU's flag has no effect on this CPU's decision to take the
// lock. The flag still serves its original purpose — guarding
// THIS CPU against its own recursive entry from a trap handler.
//
// Pre-BSP-install gating: CurrentCpuIdOrBsp() returns 0 before
// BSP install completes; per-CPU storage at slot 0 is the BSP
// slot post-install too, so the early-boot path sees the same
// slot before and after install. Safe.
constinit volatile u32 g_serial_in_progress_per_cpu[::duetos::acpi::kMaxCpus] = {};

inline volatile u32* SerialInProgressSlot()
{
    const u32 id = ::duetos::cpu::CurrentCpuIdOrBsp();
    return &g_serial_in_progress_per_cpu[(id < ::duetos::acpi::kMaxCpus) ? id : 0u];
}

// "Is THIS CPU currently inside a SerialWrite critical section?" —
// the cross-CPU-safe replacement for the old `g_serial_in_progress`
// global read. Reads only this CPU's slot.
inline bool SerialInProgressOnThisCpu()
{
    return *SerialInProgressSlot() != 0;
}

// Monotonically-increasing byte counter, bumped on every byte that
// reaches the UART. Used by the init-wedge watchdog in
// `arch/x86_64/timer.cpp` to detect "nothing has been logged in N
// seconds while the timer was still firing", which catches a
// non-progressing driver bring-up (xHCI reset deadlock, locked
// mutex, busy-spin) before it eats the boot timeout. Read via
// `SerialBytesWritten()` below — non-atomic on 8-byte aligned u64
// loads is fine on x86_64 single-CPU.
constinit u64 g_serial_bytes_written = 0;

// Drive the UART directly. No locking, no panic-mode check — the
// callers above have already decided whether they hold the lock or
// have bypassed it. Each byte spins on the LSR transmit-empty bit
// until the previous byte has cleared the THR.
void WriteByteRaw(u8 byte)
{
    while ((Inb(kCom1Port + kRegLineStatus) & kLsrTransmitEmpty) == 0)
    {
        // Spin until the transmitter holding register is empty.
    }
    Outb(kCom1Port + kRegData, byte);
    ++g_serial_bytes_written;
}

void WriteCharRaw(char c)
{
    if (c == '\0')
    {
        return;
    }
    if (c == '\n')
    {
        WriteByteRaw('\r');
    }
    WriteByteRaw(static_cast<u8>(c));
}

} // namespace

void SerialInit()
{
    // Disable all UART interrupts — we poll.
    Outb(kCom1Port + kRegInterruptEn, 0x00);

    // Enable DLAB so the next two writes set the divisor.
    Outb(kCom1Port + kRegLineControl, kLcrDlab);

    // 115200 baud: divisor = 115200 / 115200 = 1.
    Outb(kCom1Port + kRegData, 0x01);
    Outb(kCom1Port + kRegInterruptEn, 0x00);

    // 8 data bits, no parity, 1 stop bit. Clears DLAB in the same write.
    Outb(kCom1Port + kRegLineControl, kLcr8N1);

    // Enable + clear FIFOs, 14-byte trigger level.
    Outb(kCom1Port + kRegFifoControl, 0xC7);

    // Assert RTS and DTR, enable auxiliary output 2 (required for IRQ routing
    // on real hardware even though we don't use interrupts here).
    Outb(kCom1Port + kRegModemControl, 0x0B);
}

i32 SerialReadByteNonblocking()
{
    // Read-side path — no spinlock. Only the serial-input pump
    // task calls this (see kernel/core/serial_input.cpp), so
    // there's no concurrent reader to race the LSR + RBR sequence.
    // Two INBs total per byte; one INB per empty poll.
    if ((Inb(kCom1Port + kRegLineStatus) & kLsrDataReady) == 0)
    {
        return -1;
    }
    return static_cast<i32>(Inb(kCom1Port + kRegData));
}

void SerialEnterPanicMode()
{
    g_serial_panic_mode = 1;
}

SerialLineGuard::SerialLineGuard() : m_flags(0), m_owned(false)
{
    // Acquire the lock and mark in-progress so nested SerialWrite*
    // calls inside the guarded scope bypass their own per-call
    // acquire and write directly under our held lock. Without this
    // multi-call sequences (a la SpawnRing3Task's
    // `[ring3] queued task name=...` chain of 9 SerialWrite calls)
    // can have another task's output interleaved at every call
    // boundary, splitting one logical line into garbage that
    // signature-grep CI tests can't match.
    //
    // Re-entrancy: if serial output is ALREADY in progress on this
    // CPU (an outer SerialLineGuard, or a SerialWrite* critical
    // section that called into code which opens a guard — e.g. the
    // nat-sysinfo structured report), this CPU already holds
    // g_serial_lock. Acquiring it again self-deadlocks (caught by
    // the ticket lock's HeldBySelf guard since sync/spinlock gained
    // deadlock-aware detection). The outer holder already provides
    // line atomicity, so the correct behaviour is to become a
    // no-op: don't acquire, don't own, let nested SerialWrite* keep
    // writing raw under the outer lock. This mirrors the existing
    // `g_serial_in_progress` bypass every SerialWrite* already has —
    // closing the asymmetry that was the actual VirtualBox boot
    // wedge (a silent hang before the detector existed).
    if (g_serial_panic_mode || SerialInProgressOnThisCpu())
    {
        return;
    }
    // Set the in-progress slot BEFORE acquiring g_serial_lock —
    // mirrors the SerialWriteX family (which already does
    // set-before / clear-after) and closes the re-entry window
    // that was the gui-fuzz SELF-DEADLOCK trigger:
    //   1. ctor enters SpinLockAcquire(g_serial_lock)
    //   2. SpinLockAcquire claims a ticket, may spin
    //   3. INSIDE that acquire (or in the slim
    //      cli-and-set-owner-cpu window AFTER ticket comes up),
    //      something on this CPU that ignores IF — NMI / MCE /
    //      a lockdep-violation logger reached from
    //      LockdepBeforeAcquire — calls SerialWrite or opens
    //      another SerialLineGuard, sees slot=0 (we haven't
    //      reached line 195 yet), and tries to acquire the same
    //      lock. The HeldBySelf guard correctly fires and
    //      panics — but it should never have been called: the
    //      legitimate "ignore the lock on re-entry" path was
    //      gated only by the slot, which we set too late.
    // Setting slot=1 first means any re-entry on this CPU during
    // the acquire takes the slot-bypass (raw serial) path.
    // Per-CPU slot, so other CPUs are unaffected.
    *SerialInProgressSlot() = 1;
    auto irq = duetos::sync::SpinLockAcquire(g_serial_lock);
    m_flags = irq.rflags;
    m_owned = true;
}

SerialLineGuard::~SerialLineGuard()
{
    // Only the guard that actually acquired releases. A panic-mode
    // or re-entrant no-op guard leaves the outer holder untouched.
    if (!m_owned)
    {
        return;
    }
    // Clear the in-progress flag BEFORE releasing the lock. The
    // ORIGINAL ordering — release-then-clear — was correct for the
    // single-CPU bypass-vs-self-recursion case the old comment
    // describes, but with the slot now PER-CPU it opened a
    // cross-CPU race: after SpinLockRelease the lock is free + IF
    // restored, but `slot=1` is still set. A peer CPU acquires the
    // lock and writes lock-protected bytes; this CPU then takes an
    // IRQ whose handler calls SerialWrite, sees `slot=1`, bypasses
    // the lock, and writes raw bytes — the streams interleave at
    // the UART (observed 2026-05-22 under SMP=8 stress as
    // `[stress] pre  hea[sched]p_used_KiB=...`).
    //
    // Clearing the slot first, while IF is still 0 (the SpinLock
    // acquire's cli is still in effect for this CPU until
    // SpinLockRelease's sti at the very end), closes the window:
    // any IRQ that fires AFTER the release sees `slot=0` and goes
    // through the normal lock-acquire path; the original
    // self-recursion concern is no longer applicable because slot
    // is per-CPU and the same-CPU IRQ would see its own slot=0
    // anyway.
    *SerialInProgressSlot() = 0;
    duetos::sync::IrqFlags flags{m_flags};
    duetos::sync::SpinLockRelease(g_serial_lock, flags);
}

void SerialWriteByte(u8 byte)
{
    if (g_serial_panic_mode || SerialInProgressOnThisCpu())
    {
        WriteByteRaw(byte);
        return;
    }
    volatile u32* slot = SerialInProgressSlot();
    *slot = 1;
    {
        duetos::sync::SpinLockGuard guard(g_serial_lock);
        WriteByteRaw(byte);
    }
    *slot = 0;
}

void SerialWrite(const char* str)
{
    if (str == nullptr)
    {
        return;
    }

    if (g_serial_panic_mode || SerialInProgressOnThisCpu())
    {
        for (const char* p = str; *p != '\0'; ++p)
        {
            WriteCharRaw(*p);
        }
        return;
    }

    volatile u32* slot = SerialInProgressSlot();
    *slot = 1;
    {
        duetos::sync::SpinLockGuard guard(g_serial_lock);
        for (const char* p = str; *p != '\0'; ++p)
        {
            WriteCharRaw(*p);
        }
    }
    *slot = 0;
}

void SerialWriteN(const char* data, u64 len)
{
    if (data == nullptr || len == 0)
    {
        return;
    }

    if (g_serial_panic_mode || SerialInProgressOnThisCpu())
    {
        for (u64 i = 0; i < len; ++i)
        {
            WriteCharRaw(data[i]);
        }
        return;
    }

    volatile u32* slot = SerialInProgressSlot();
    *slot = 1;
    {
        duetos::sync::SpinLockGuard guard(g_serial_lock);
        for (u64 i = 0; i < len; ++i)
        {
            WriteCharRaw(data[i]);
        }
    }
    *slot = 0;
}

void SerialWriteHex(u64 value)
{
    static constexpr char kDigits[] = "0123456789abcdef";

    if (g_serial_panic_mode || SerialInProgressOnThisCpu())
    {
        WriteByteRaw('0');
        WriteByteRaw('x');
        for (int shift = 60; shift >= 0; shift -= 4)
        {
            WriteByteRaw(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
        }
        return;
    }

    volatile u32* slot = SerialInProgressSlot();
    *slot = 1;
    {
        duetos::sync::SpinLockGuard guard(g_serial_lock);
        WriteByteRaw('0');
        WriteByteRaw('x');
        for (int shift = 60; shift >= 0; shift -= 4)
        {
            WriteByteRaw(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
        }
    }
    *slot = 0;
}

// ---------------------------------------------------------------------------
// COM2 — dedicated to the GDB stub. No locking: the stop loop has
// exclusive ownership when GDB is attached, and the rest of the
// kernel never writes to this port.
// ---------------------------------------------------------------------------
void SerialCom2Init()
{
    Outb(kCom2Port + kRegInterruptEn, 0x00); // poll, no IRQ
    Outb(kCom2Port + kRegLineControl, kLcrDlab);
    Outb(kCom2Port + kRegData, 0x01); // divisor low — 115200 baud
    Outb(kCom2Port + kRegInterruptEn, 0x00);
    Outb(kCom2Port + kRegLineControl, kLcr8N1);
    Outb(kCom2Port + kRegFifoControl, 0xC7);
    Outb(kCom2Port + kRegModemControl, 0x0B);
}

void SerialCom2WriteByte(u8 byte)
{
    while ((Inb(kCom2Port + kRegLineStatus) & kLsrTransmitEmpty) == 0)
    {
        // spin
    }
    Outb(kCom2Port + kRegData, byte);
}

u8 SerialCom2ReadByteBlocking()
{
    while ((Inb(kCom2Port + kRegLineStatus) & kLsrDataReady) == 0)
    {
        // spin
    }
    return Inb(kCom2Port + kRegData);
}

duetos::i32 SerialCom2ReadByteNonblocking()
{
    if ((Inb(kCom2Port + kRegLineStatus) & kLsrDataReady) == 0)
    {
        return -1;
    }
    return static_cast<duetos::i32>(Inb(kCom2Port + kRegData));
}

u64 SerialBytesWritten()
{
    return g_serial_bytes_written;
}

} // namespace duetos::arch
