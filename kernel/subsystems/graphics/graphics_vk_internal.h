#pragma once

#include "util/types.h"

/*
 * DuetOS — Vulkan ICD internal interface.
 *
 * Tiny shared surface used to split the Vulkan ICD across more
 * than one TU.  At present only `graphics_vk.cpp` (the API
 * implementation) and `graphics_vk_selftest.cpp` (the boot
 * self-test) cooperate through this header.
 *
 * Discipline:
 *   - Anything that must be reachable across TUs lives here as
 *     a thin function declaration.
 *   - Storage for the counters lives in `graphics_vk.cpp`'s
 *     anonymous namespace; this header only exposes read
 *     accessors so the selftest can assert progress without
 *     reaching into the implementation TU's static state.
 *   - The leak check is declared here too so the selftest TU
 *     doesn't need to know which handle pools exist.
 *
 * Not part of the public Vulkan ICD surface.  Userland code
 * never includes this file — it's strictly an internal
 * boundary between two kernel TUs.
 */

namespace duetos::subsystems::graphics::internal
{

// ----- counter accessors used by the boot self-test ----------------

u32 DynamicRenderingsCount();
u32 SecondaryExecutesCount();
u32 SecondaryOpsReplayedCount();
u32 PushDescriptorWritesCount();
u32 InvalidSpirvRejectionsCount();
u32 CommandRecordedCount();
u32 CommandReplayedCount();
u32 SpirvModulesParsedCount();
u32 SpirvEntryPointsSeenCount();
u32 SpirvCapabilitiesSeenCount();

// ----- leak check ---------------------------------------------------
//
// Walks every per-kind handle pool and asserts each pool's live
// count is zero.  Logs a WARN via KLOG_* identifying the leaking
// pool name on failure.  Returns true on a clean run.

bool LeakCheckHandlePools();

} // namespace duetos::subsystems::graphics::internal
