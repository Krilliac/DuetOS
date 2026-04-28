#pragma once

#include "util/types.h"

/*
 * DuetOS — GDB remote serial protocol stub, v0 scaffolding (plan D7).
 *
 * WHAT
 *   Parser + framer for the GDB remote serial protocol over
 *   COM2 (or another configured serial port). Once attached,
 *   GDB sends `$<packet>#<csum>` strings and expects either an
 *   ACK (`+`) followed by the response packet, or a NAK (`-`)
 *   to retry. v0 implements the framing + checksum +
 *   ACK/NAK protocol, plus a minimal handler table for the
 *   commands every GDB session uses on connect.
 *
 * SCOPE FOR v0
 *   - Wire protocol: `$packet#csum` framing, `+` / `-` ack,
 *     hex-encoded reply.
 *   - Commands recognised:
 *       qSupported       — feature negotiation; returns a fixed
 *                          v0 capability string.
 *       ?                — halt-reason; returns S05 (SIGTRAP).
 *       g                — read all registers; v0 returns zeros.
 *       G<hex>           — write all registers; v0 ignores +ACKs.
 *       m<addr>,<len>    — read memory; v0 returns 00 bytes.
 *       M<addr>,<len>:<hex> — write memory; v0 ignores +ACKs.
 *       Hg / Hc          — set thread; v0 OK.
 *       k                — kill / detach; v0 OK then disconnects.
 *     Anything else returns the empty packet `$#00` ("unsupported").
 *   - Single-byte input source: `GdbStubReceiveByte(b)` is the
 *     canonical entry point. v0 doesn't yet hook this into the
 *     serial RX path — landing the parser first lets the wiring
 *     be a one-line call from the COM2 IRQ handler when GDB
 *     attach time arrives.
 *
 * NOT IN SCOPE
 *   - Actually reading / writing real CPU registers (the `g` /
 *     `G` reply path returns zeros; the trap-frame plumbing
 *     lands as a D7-followup once a single-step / breakpoint
 *     debugger workflow is in active use).
 *   - Memory access against the live kernel (the `m` / `M`
 *     reply path returns zeros; gating against the `extable`
 *     so a bad address from GDB doesn't fault the kernel is
 *     also a D7-followup).
 *   - Continue / step / breakpoint commands (`c` / `s` / `Z` /
 *     `z`) — they all reduce to bookkeeping over the stop-
 *     reason state machine, which we'll grow once the live
 *     paths above exist.
 *
 * THREADING
 *   The stub runs from the serial RX context. v0 single-CPU;
 *   per-CPU stop-state lands once SMP exposes the current-CPU
 *   ID (mirrors the lockdep / event_trace / soft_lockup
 *   per-CPU prep pattern).
 */

namespace duetos::diag::gdb
{

/// Maximum packet size GDB will ever send / receive. The
/// protocol gives a 4 KiB hint via `qSupported`; v0 uses 1 KiB
/// which is enough for `g` / `m` over a 16-register kernel
/// snapshot.
inline constexpr u32 kPacketMax = 1024;

/// Output sink — invoked once per byte the stub wants to send
/// over the serial line. v0 caller wires this to a
/// `arch::SerialWritePort(byte)` via a function pointer so the
/// stub TU stays portable across COM ports.
using GdbStubWriteByte = void (*)(u8 byte);

/// Configure the output sink. Call once at boot before the
/// first byte arrives; later changes are racy.
void GdbStubSetSink(GdbStubWriteByte sink);

/// Feed one received byte to the parser. The state machine
/// recognises the `$` / `#` framing, accumulates the body,
/// validates the trailing checksum, and on a complete packet
/// dispatches to the relevant handler. Cheap; safe from any
/// context including IRQ.
void GdbStubReceiveByte(u8 byte);

/// Diagnostic counters.
u64 GdbStubPacketsReceived();
u64 GdbStubPacketsBadChecksum();
u64 GdbStubPacketsHandled();

/// Boot-time self-test. Drives a synthesised conversation
/// (operator sends `qSupported`, halt-reason, `g`) through
/// `GdbStubReceiveByte` with a capturing sink; asserts the
/// reply for each is well-framed and the checksum matches.
/// Panics on mismatch.
void GdbStubSelfTest();

} // namespace duetos::diag::gdb
