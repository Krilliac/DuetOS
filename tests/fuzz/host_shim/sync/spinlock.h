#pragma once

#include "util/types.h"

namespace duetos::sync
{
struct SpinLock
{
    volatile u32 locked;
    volatile u32 owner_cpu;
    u16 class_id;
};
struct IrqFlags
{
    u64 rflags;
};
inline IrqFlags SpinLockAcquire(SpinLock&)
{
    return IrqFlags{0};
}
inline void SpinLockRelease(SpinLock&, IrqFlags) {}
} // namespace duetos::sync
