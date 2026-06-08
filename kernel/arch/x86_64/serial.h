#pragma once

#include "util/types.h"

/*
 * 16550-compatible UART for early kernel output. This is the only output
 * path available before the real console/log subsystem is initialized,
 * and the single path used by QEMU's `-serial stdio` for boot diagnostics.
 *
 * Concurrency: the public Write* entry points serialise on a per-port
 * spinlock so concurrent CPUs / preempting tasks can't byte-interleave
 * mid-string. Each call to SerialWrite/N/Hex/Byte is atomic at the
 * function level — the bytes a single call emits land contiguously in
 * the serial output. Composed log lines built from multiple calls
 * (e.g. SerialWrite + SerialWriteHex + SerialWrite("\n")) can still
 * interleave at the call boundary; that's the same boundary as before
 * the lock was added and is the right granularity for boot-log
 * readability.
 *
 * Panic re-entrancy: SerialEnterPanicMode (called by core::Panic before
 * the first banner SerialWrite) flips a bypass that suppresses the lock
 * so a panic on a CPU that was already holding the lock — or a panic
 * fired from within SerialWrite — still gets its banner out instead of
 * self-deadlocking.
 *
 * Panic SMP serialization: while the bypass above keeps a panic dump
 * alive past a wedged lock holder, byte-level interleaving between two
 * concurrent panic-mode emitters (canonical case: BSP panic dump + an
 * AP-side `HaltOnRecursiveFault` after the AP took its own trap before
 * the panic-broadcast NMI drained) corrupts the second writer's output.
 * Inside the bypass path each panic-mode SerialWrite* try-claims a
 * single-u32 panic-emit owner with a bounded spin; on success it holds
 * the claim across its own byte writes and releases on the way out, so
 * two panic-mode emitters serialize their bursts at the call boundary.
 * On claim timeout (genuinely wedged peer) the writer falls through to
 * raw bytes — original wedged-holder escape preserved. Independent of
 * `g_serial_lock` so the recursive-fault path doesn't drag the heavy
 * spinlock + lockdep machinery into a possibly-corrupt-stack context.
 *
 * Context: kernel. Safe to call from task context, IRQ context, and
 * panic / trap context.
 */

namespace duetos::arch
{

/// COM1 I/O base port on standard PC hardware.
inline constexpr u16 kCom1Port = 0x3F8;

/// COM2 I/O base port — used by the GDB remote-serial-protocol stub
/// (see `kernel/diag/gdb_server.{h,cpp}`). Kept off the human log
/// stream on COM1 so kernel printf and a live GDB session don't
/// fight for the same wire.
inline constexpr u16 kCom2Port = 0x2F8;

/// Initialize COM1 to 115200 baud, 8N1, FIFO enabled, interrupts disabled.
/// Safe to call before any other subsystem.
void SerialInit();

/// Same shape as `SerialInit` but for COM2. Idempotent. Wired
/// from `kernel_main` only when DUETOS_GDB_SERVER is enabled —
/// otherwise the port stays untouched (and the GDB stub stays
/// dormant).
void SerialCom2Init();

/// Write one byte to COM2, polling LSR until the THR is empty.
/// No locking — the GDB stub is single-flight by construction
/// (one CPU is paused in the stop loop while peers are NMI-halted
/// or simply not driving the stub).
void SerialCom2WriteByte(u8 byte);

/// Block until a byte arrives on COM2's RBR, then return it.
/// Used by the GDB stub's stop loop to pump bytes from the
/// remote debugger.
u8 SerialCom2ReadByteBlocking();

/// Non-blocking COM2 read. Returns the byte in the low 8 bits,
/// or -1 if the RBR is empty. Lets the stub poll for "is there
/// a control packet waiting?" without committing to a blocking
/// wait.
duetos::i32 SerialCom2ReadByteNonblocking();

/// Write a single byte to COM1 (polling — blocks until THR is empty).
/// Acquires the serial spinlock for the duration of one byte.
void SerialWriteByte(u8 byte);

/// Write a NUL-terminated string to COM1. Atomic at the function level —
/// no other writer interleaves between this call's bytes.
void SerialWrite(const char* str);

/// Write exactly `len` bytes to COM1 from `data`. Atomic at the function
/// level. Mirrors SerialWrite's LF->CRLF behavior and ignores embedded
/// NUL bytes.
void SerialWriteN(const char* data, u64 len);

/// Write a 64-bit value as "0x" + 16 hex digits, no newline. Atomic at
/// the function level.
void SerialWriteHex(u64 value);

/// Monotonically-increasing count of bytes that have reached the
/// UART since boot. Sampled by the init-wedge watchdog in the
/// timer IRQ to detect "no progress has been logged in N seconds
/// while the timer kept firing" — the canonical signature of a
/// driver bring-up deadlock (xHCI reset wait, locked mutex,
/// non-responding MMIO poll). Reads are unsynchronised; an 8-byte
/// load is atomic on x86_64 and the writer is the single boot CPU.
u64 SerialBytesWritten();

/// Count of serial bytes dropped by the bounded TX-drain spin (a UART
/// backend that back-pressured past kTxDrainSpinBudget). 0 on a healthy
/// boot; non-zero indicates the once-kernel-wedging stuck-transmitter
/// condition was hit and safely absorbed (byte dropped, kernel survived).
u64 SerialBytesDropped();

/// Non-blocking read of one byte from COM1. Returns the received byte
/// in the low 8 bits, or -1 if the receive buffer is empty. The serial
/// receive path is intentionally lock-free: only the per-CPU input
/// pump task calls this, so contention is impossible. Costs one INB on
/// the LSR + (when ready) one INB on the RBR.
duetos::i32 SerialReadByteNonblocking();

/// Bypass the serial spinlock from this point on. Called by core::Panic
/// before the panic banner so a panic that fires while another CPU was
/// already mid-SerialWrite still gets its output. Once set, never
/// cleared — the kernel halts anyway.
void SerialEnterPanicMode();

/// Write exactly `len` bytes from a pre-built buffer in recursive-fault
/// context. Safe to call while g_serial_lock may be held by another CPU,
/// with broken page-tables, and with a possibly-corrupt stack.
///
/// Strategy (two-level serialization):
///   1. Try-acquire g_serial_lock with a single non-blocking attempt. If
///      acquired, emit under the lock and release — same atomicity as a
///      normal SerialWriteN call. This is the common case: the BSP's
///      first panic line has finished before any AP reaches here.
///   2. If the lock is busy or self-held — the BSP is mid-dump and has
///      already set panic mode — fall through to the PanicEmitTryClaim
///      bounded-spin serializer so concurrent panic-mode writers don't
///      byte-interleave.
///
/// Never blocks. Never panics. Never allocates. The caller must
/// pre-format the entire line into a stack buffer and pass it here as a
/// single contiguous region; that makes the emit atomic at the call
/// boundary under either serialization path.
void SerialWriteNRecursiveFault(const char* data, u64 len);

/// RAII guard that holds the per-port serial spinlock for an entire
/// scope. Use it to make a sequence of SerialWrite/SerialWriteHex
/// calls atomic at the *line* level (or any granularity larger than
/// one call). Inside the guard's scope, every Write* function sees
/// the in-progress flag set and bypasses the per-call lock acquire,
/// so nested calls don't try to re-lock — they write under the
/// already-held lock.
///
///   {
///       arch::SerialLineGuard guard;
///       arch::SerialWrite("[foo] thing=");
///       arch::SerialWriteHex(value);
///       arch::SerialWrite(" pid=");
///       arch::SerialWriteHex(pid);
///       arch::SerialWrite("\n");
///   }
///
/// Without the guard, those five calls each take + release the lock
/// independently. With ANOTHER task printing concurrently, the second
/// task's output can interleave at the call boundaries — splitting
/// one logical line across two physical lines and breaking
/// signature-grep CI tests that look for the line as a single
/// substring.
///
/// Cost: one SpinLockAcquire on construct + one SpinLockRelease on
/// destroy. IRQs are disabled for the duration of the scope; keep
/// the body short and avoid blocking calls.
class SerialLineGuard
{
  public:
    SerialLineGuard();
    ~SerialLineGuard();

    SerialLineGuard(const SerialLineGuard&) = delete;
    SerialLineGuard& operator=(const SerialLineGuard&) = delete;
    SerialLineGuard(SerialLineGuard&&) = delete;
    SerialLineGuard& operator=(SerialLineGuard&&) = delete;

  private:
    duetos::u64 m_flags;
    // True only when THIS guard actually acquired g_serial_lock. A
    // guard constructed while serial output is already in progress on
    // this CPU (outer SerialLineGuard / SerialWrite* critical section,
    // or panic raw-mode) is a re-entrant no-op — it must NOT acquire
    // (self-deadlock) and its destructor must NOT release/clear.
    bool m_owned;
};

} // namespace duetos::arch
