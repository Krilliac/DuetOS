#pragma once

namespace duetos::arch
{

/// Retarget MSR_LSTAR at the SYSCALL entry stub matching the given
/// ABI: `true` for Linux, `false` for native DuetOS. Called by the
/// scheduler at task-switch when the incoming task's
/// `Process::abi_flavor` differs from the previous task's. A no-op
/// in spirit on switches that don't cross an ABI boundary — the
/// caller is expected to skip it in that case to avoid a wrmsr per
/// switch.
void SyscallRetargetForAbi(bool linux_abi);

} // namespace duetos::arch
