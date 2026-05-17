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
 *   - Single-byte input source: `GdbServerReceiveByte(b)` is the
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

/// Maximum packet size GDB will ever send / receive. Bumped
/// to 4 KiB so the `g` reply (1080 hex chars for GPRs + FPU/SSE
/// padding GDB's default x86_64 target expects) fits with
/// margin for the surrounding `$...#csum` framing, AND `m`
/// memory reads can return up to ~2 KiB at a time.
inline constexpr u32 kPacketMax = 4096;

/// Output sink — invoked once per byte the stub wants to send
/// over the serial line. v0 caller wires this to a
/// `arch::SerialWritePort(byte)` via a function pointer so the
/// stub TU stays portable across COM ports.
using GdbServerWriteByte = void (*)(u8 byte);

/// Configure the output sink. Call once at boot before the
/// first byte arrives; later changes are racy.
void GdbServerSetSink(GdbServerWriteByte sink);

/// Snapshot of the 16 general-purpose x86_64 registers + RIP +
/// RFLAGS that GDB's `g` packet returns. Layout matches GDB's
/// canonical x86_64 register order (rax / rbx / rcx / rdx / rsi
/// / rdi / rbp / rsp / r8..r15 / rip / rflags / cs / ss / ds /
/// es / fs / gs). v0 reports zeros for the segment registers
/// since the trap-frame snapshot doesn't preserve them today.
struct GdbServerRegSnapshot
{
    u64 rax, rbx, rcx, rdx;
    u64 rsi, rdi, rbp, rsp;
    u64 r8, r9, r10, r11;
    u64 r12, r13, r14, r15;
    u64 rip, rflags;
    u32 cs, ss, ds, es, fs, gs;
};

/// Publish a register snapshot. Subsequent `g` packets will
/// hex-encode this struct in the canonical GDB order. Pass
/// nullptr to clear (snapshots stop being live; `g` reverts to
/// returning zeros). Caller owns the storage; the stub holds a
/// pointer, so the snapshot must outlive any pending `g` reply.
///
/// `mut_snap` is the same pointer kept as a non-const sibling
/// for `G` (write registers) — when non-null, GDB writes apply
/// in-place; when null, `G` is silently dropped.
void GdbServerPublishRegisters(const GdbServerRegSnapshot* snap);

/// Publish a writable register snapshot for the `G` packet
/// (GDB writes back the register state). Pass nullptr to make
/// `G` a silent no-op (returns OK without applying). Typical
/// pairing: one trap-frame snapshot used for both Get and
/// Set.
void GdbServerPublishWritableRegisters(GdbServerRegSnapshot* snap);

/// Feed one received byte to the parser. The state machine
/// recognises the `$` / `#` framing, accumulates the body,
/// validates the trailing checksum, and on a complete packet
/// dispatches to the relevant handler. Cheap; safe from any
/// context including IRQ.
void GdbServerReceiveByte(u8 byte);

/// Diagnostic counters.
u64 GdbServerPacketsReceived();
u64 GdbServerPacketsBadChecksum();
u64 GdbServerPacketsHandled();

/// Boot-time self-test. Drives a synthesised conversation
/// (operator sends `qSupported`, halt-reason, `g`) through
/// `GdbServerReceiveByte` with a capturing sink; asserts the
/// reply for each is well-framed and the checksum matches.
/// Panics on mismatch.
void GdbServerSelfTest();

// ---------------------------------------------------------------------------
// Live-debug stop loop
// ---------------------------------------------------------------------------

/// Wire the stub's I/O to COM2 (GdbServerSetSink → SerialCom2WriteByte
/// + RX pump fed from SerialCom2ReadByteBlocking). Idempotent. Call
/// from kernel_main when DUETOS_GDB_SERVER is enabled.
void GdbServerInitCom2();

/// Reason a stop packet was sent — feeds the `T<sig>` payload.
enum class StopReason : duetos::u8
{
    Trap,       // generic trap (default — SIGTRAP)
    SoftBreak,  // int3 from a Z0 (software) breakpoint
    SingleStep, // #DB after RFLAGS.TF set by a previous `s`
    UserHalt,   // operator-initiated pause (Ctrl-C / vCont? path)
};

/// Publish the registers, broadcast a stop packet to the attached
/// debugger, and pump GDB packets until the debugger issues a
/// resume command (`c` / `s` / `D` / `k`). Returns when the
/// debugger has resumed; the caller (typically the int3 / debug
/// trap handler) then returns from the trap normally.
///
/// Caller must:
///   - Have already published a writable register snapshot via
///     GdbServerPublishRegisters + GdbServerPublishWritableRegisters
///     so `g`/`G` see the live trap-frame and `c` can pick up
///     register edits the debugger made.
///   - Know that the `s` (step) handler sets RFLAGS.TF in the
///     writable snapshot — the next iretq exits the stop loop and
///     the next instruction triggers #DB, which re-enters this
///     same routine through the trap path.
void GdbServerEnterAndWait(StopReason reason);

/// Read what the most recent stop loop's resume command was.
/// Used by the trap dispatcher to decide whether to wire a single
/// step (clear TF after the next #DB) or just continue.
enum class ResumeAction : duetos::u8
{
    Continue,
    Step,
    Detached,
    Killed,
};
ResumeAction GdbServerLastResume();

/// Read-only view of the running-CPU register snapshot the stop
/// loop last published (RIP/RSP/RBP etc. at the stop point). Used
/// by the `monitor duet dump` verb to emit a minidump from the
/// stop-point context. Valid only while inside the stop loop.
const GdbServerRegSnapshot& GdbServerTrapSnapshot();

} // namespace duetos::diag::gdb

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::diag::gdb
{

/// Trap-dispatcher entry point: route an int3 (#BP) trap into
/// the GDB stop loop. Returns true if GDB was wired AND handled
/// the trap (caller should return from the dispatcher after
/// applying the snapshot back to the trap frame). Returns false
/// when the stub isn't initialised — caller falls through to
/// the existing recoverable-trap path.
///
/// The trap-frame's RIP is rolled back by 1 to match the
/// software-breakpoint convention (int3 is a TRAP — RIP saved
/// post-instruction; GDB and the resume cycle expect RIP at
/// the int3 site).
bool HandleSoftwareBreakpoint(arch::TrapFrame* frame);

/// Trap-dispatcher entry point: route a #DB (debug exception)
/// into the GDB stop loop. Same return convention as
/// HandleSoftwareBreakpoint. Used after a `s` (single-step)
/// resume — the kernel set RFLAGS.TF, executed one instruction,
/// and got #DB; this routes the new state back to the debugger.
bool HandleDebugException(arch::TrapFrame* frame);

/// IRQ-dispatcher hook for asynchronous stop (GDB Ctrl-C).
///
/// Polls COM2 RX non-blocking for an ETX (0x03) byte — the way
/// GDB signals "interrupt the target" mid-run, outside the
/// `$packet#csum` framing. When seen, routes `frame` through the
/// stop loop with reason `UserHalt`, so the resulting GDB stop
/// reflects "where the kernel actually was when the IRQ fired"
/// (the interrupted code's RIP) rather than "inside the polling
/// thread". The kernel resumes from the IRQ normally once the
/// debugger issues `c` / `D` / `k` / `s`.
///
/// Returns true iff a stop was injected. Caller should still
/// proceed with EOI / resched / iretq after the call returns —
/// the stop loop blocks the calling CPU until the debugger
/// resumes, then this function returns.
///
/// Cheap when no Ctrl-C is pending (one INB on the COM2 LSR).
/// Safe to call from any IRQ context; re-entrancy is impossible
/// because the stop loop runs with IF=0.
bool PollAsyncStop(arch::TrapFrame* frame);

} // namespace duetos::diag::gdb
