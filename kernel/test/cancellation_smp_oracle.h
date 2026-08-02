#pragma once

namespace duetos::test
{

/// Run the focused SMP cancellation oracle used by
/// `smoke=cancellation-smp`. The caller must be ordinary task context after
/// SMP and Userland bring-up. Every internal wait has a finite recovery bound;
/// false means a verdict-bearing failure line was already emitted.
bool RunCancellationSmpOracle();

} // namespace duetos::test
