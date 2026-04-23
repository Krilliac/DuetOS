#pragma once

/*
 * Debug breakpoint syscall handlers — extracted from
 * core/syscall.cpp so the dispatcher stays a thin router.
 *
 *   SYS_BP_INSTALL (38) — rdi=va, rsi=kind|flags, rdx=len
 *   SYS_BP_REMOVE  (39) — rdi=bp_id
 *
 * Both are cap-gated on kCapDebug; denials record against the
 * sandbox-denial counter with rate-limited log lines (same
 * pattern the file/stat handlers use).
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::debug
{

void DoBpInstall(arch::TrapFrame* frame);
void DoBpRemove(arch::TrapFrame* frame);

} // namespace customos::debug
