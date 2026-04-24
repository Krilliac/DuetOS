#pragma once

/*
 * Win32 TLS (TlsAlloc/Free/GetValue/SetValue) syscall handlers.
 *
 *   SYS_TLS_ALLOC (34) — returns slot idx or u64(-1) on full/err.
 *   SYS_TLS_FREE  (35) — rdi=idx. Clears allocation bit + value.
 *   SYS_TLS_GET   (36) — rdi=idx. Returns stored value (0 if
 *                        unallocated, per Win32 contract).
 *   SYS_TLS_SET   (37) — rdi=idx, rsi=value.
 *
 * Backed by Process::tls_slot_in_use (64-bit bitmap) +
 * tls_slot_value[Process::kWin32TlsCap]. Per-process, single-
 * threaded for v0 — "thread-local" == "process-local" until we
 * grow multiple tasks per process.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoTlsAlloc(arch::TrapFrame* frame);
void DoTlsFree(arch::TrapFrame* frame);
void DoTlsGet(arch::TrapFrame* frame);
void DoTlsSet(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
