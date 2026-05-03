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
 * Context: kernel. Safe to call from task context, IRQ context, and
 * panic / trap context.
 */

namespace duetos::arch
{

/// COM1 I/O base port on standard PC hardware.
inline constexpr u16 kCom1Port = 0x3F8;

/// Initialize COM1 to 115200 baud, 8N1, FIFO enabled, interrupts disabled.
/// Safe to call before any other subsystem.
void SerialInit();

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
};

} // namespace duetos::arch
