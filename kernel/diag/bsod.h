#pragma once

#include "util/types.h"

/*
 * DuetOS — fullscreen panic UI ("Blue Screen of Death").
 *
 * Called from `Panic()` / `PanicWithValue()` (kernel/core/panic.cpp)
 * AFTER the serial / minidump dump is complete, BEFORE the final
 * `arch::Halt()`. Replaces what was previously "halt forever with
 * no on-screen signal" with a fullscreen panel that shows:
 *
 *   - Title strip ("DUETOS — A FATAL ERROR OCCURRED")
 *   - Subsystem + message + optional value
 *   - Faulting RIP, symbolised via util::ResolveAddress
 *   - Selected register snapshot (RSP, RBP)
 *   - Tail of the kernel log ring (last ~20 entries) via
 *     `klog::DumpLogRingTo` with a buffered sink
 *   - Footer "PRESS ANY KEY TO REBOOT"
 *
 * On any key from the PS/2 controller, issues an 8042 reset
 * (write 0xFE to port 0x64). The classic x86 reset trick — works
 * on every host platform the framebuffer console works on,
 * needs no ACPI dependency.
 *
 * Constraints:
 *   - Must NOT acquire compositor / scheduler / heap locks.
 *     `Panic()` may be called with those held. The BSOD writes
 *     directly to the framebuffer via Framebuffer* primitives,
 *     which are documented as panic-safe (no internal locking,
 *     no allocation).
 *   - Must NOT allocate from the heap. All buffers are static
 *     globals or stack-local.
 *   - Must NOT depend on IRQs. The PS/2 poll uses 8042 status-
 *     port polling, not the normal IRQ-driven keyboard reader.
 *   - Must tolerate an absent framebuffer. If
 *     `FramebufferAvailable()` returns false (boot before video
 *     init, or unusual UEFI handoff), the function returns
 *     immediately and the caller falls through to `arch::Halt()`
 *     as before.
 *
 * Studied ToaruOS for prior art on fullscreen-panic UIs — no
 * direct equivalent there; the panel layout below is original
 * DuetOS work.
 *
 * Context: kernel. Called only from the panic path. The
 * function does not return on success (it issues the reset); it
 * returns to the caller only if the framebuffer is unavailable
 * or polling for the reset key was aborted by a recursive fault.
 */

namespace duetos::diag
{

/// Render the BSOD and poll for keypress. `subsystem` and
/// `message` are the same strings passed to `Panic()`; `rip` is
/// the address the diagnostic dump used (typically the panic
/// site's return address). If `has_value` is true, `value` is
/// shown alongside the message (matching `PanicWithValue`).
void BsodRender(const char* subsystem, const char* message, duetos::u64 rip, duetos::u64 rsp, duetos::u64 rbp,
                duetos::u64 value, bool has_value);

} // namespace duetos::diag
