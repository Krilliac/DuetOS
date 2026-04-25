#pragma once

#include "types.h"

namespace duetos::core
{

// Symbolic names for opaque numeric values that show up in logs.
// Each function returns a static const char* — never null, never
// owned by the caller, safe to print from any context (including
// IRQ / panic). For numbers outside the known range, the
// returned string is "?" so callers don't have to special-case
// missing entries.

const char* SyscallName(u64 num);
const char* LinuxSyscallName(u64 nr);
const char* WifiSecurityName(u64 sec);
const char* FwSourcePolicyName(u64 policy);

} // namespace duetos::core
