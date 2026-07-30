#pragma once

/*
 * Win32 Fiber + Fiber-Local Storage (FLS) syscall handlers.
 *
 *   SYS_FIBER_CONVERT (216) — convert thread to fiber.
 *   SYS_FIBER_CREATE  (217) — create a new fiber with its own stack.
 *   SYS_FIBER_SWITCH  (218) — save/restore GP regs + RSP + RIP.
 *   SYS_FIBER_DELETE  (219) — free fiber slot + stack.
 *   SYS_FLS_ALLOC     (220) — allocate a per-process FLS slot.
 *   SYS_FLS_FREE      (221) — free a FLS slot.
 *   SYS_FLS_GET       (222) — read per-fiber FLS value.
 *   SYS_FLS_SET       (223) — write per-fiber FLS value.
 *
 * Fiber context is saved/restored through the trap frame: the syscall
 * handler manipulates the TrapFrame fields that iretq will restore,
 * so the target fiber resumes at its saved RIP with its saved RSP.
 *
 * FLS is separate from TLS: FLS values are per-FIBER, TLS values are
 * per-THREAD. When a thread is not a fiber, FLS falls back to per-
 * thread storage (one implicit fiber context per thread).
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoFiberConvert(arch::TrapFrame* frame);
void DoFiberCreate(arch::TrapFrame* frame);
void DoFiberSwitch(arch::TrapFrame* frame);
void DoFiberDelete(arch::TrapFrame* frame);
void DoFlsAlloc(arch::TrapFrame* frame);
void DoFlsFree(arch::TrapFrame* frame);
void DoFlsGet(arch::TrapFrame* frame);
void DoFlsSet(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
