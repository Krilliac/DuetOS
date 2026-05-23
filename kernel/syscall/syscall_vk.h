#pragma once

#include "arch/x86_64/traps.h"

/*
 * DuetOS — SYS_VK_CALL dispatch.
 *
 * The in-kernel Vulkan ICD exposes its API through a single
 * syscall (`SYS_VK_CALL`, number 211) with an op-code dispatch on
 * the first argument. Userland — specifically the
 * `userland/libs/vulkan_1/vulkan-1.dll` PE library — issues the
 * syscall with `rdi` set to one of the `VkOp` values in
 * `syscall.h`, and the remaining argument registers carry the
 * per-op arguments.
 *
 * Why one syscall instead of one per Vulkan entry point: Vulkan
 * is ~600 entry points; baking each into a syscall number would
 * burn the entire remaining slot space. The op-code dispatch
 * keeps the kernel's syscall ABI compact while preserving a
 * stable per-op ABI.
 *
 * Capability gating: today the cap-gate lives one layer up — at
 * the Win32-side entry the PE binary goes through. A future
 * `kCapGraphics` slice will gate at this layer too.
 *
 * Context: kernel. Called from `SyscallDispatch` in
 * `syscall.cpp` when the syscall number matches `SYS_VK_CALL`.
 */

namespace duetos::syscall
{

/// Dispatch a SYS_VK_CALL trap to the appropriate kernel ICD
/// entry. Reads `frame->rdi` as the `VkOp` selector and routes
/// to `subsystems::graphics::Vk*` calls; writes the return value
/// into `frame->rax`. Bad op-codes return 0xFFFFFFFFFFFFFFFFu
/// (all ones) so the userland caller can distinguish "kernel
/// doesn't know this op" from a legitimate zero return.
void DoVkCall(arch::TrapFrame* frame);

} // namespace duetos::syscall
