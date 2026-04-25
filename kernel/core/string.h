#pragma once

#include "types.h"

/*
 * DuetOS — freestanding string operations.
 *
 * The kernel can't lean on a hosted libc. This header surfaces the
 * three primitives every C++ codegen path needs: memset, memcpy,
 * memmove. They're declared `extern "C"` because the compiler emits
 * unmangled calls to them when it lowers `T = {}` zero-init or
 * struct-copy expressions.
 *
 * The actual implementations live in `kernel/core/string.cpp`. They
 * are byte-oriented and SSE-free (the kernel runs `-mno-sse`); fast
 * enough for boot-time setup, copy-once tasks, and the occasional
 * IRQ-context move. Hot paths that need bulk throughput should reach
 * for an explicitly-vectorized helper, not memcpy.
 *
 * `memcpy` aliases to `memmove` — the strict-no-overlap guarantee
 * isn't worth a separate body when the trivial loop is already this
 * cheap.
 */

extern "C" void* memset(void* dst, int c, duetos::usize n);
extern "C" void* memmove(void* dst, const void* src, duetos::usize n);
extern "C" void* memcpy(void* dst, const void* src, duetos::usize n);

namespace duetos::core
{

/// Self-test: covers memset (length 0, partial range, full range,
/// value masking to low byte), memcpy (length 0, full copy, partial
/// preservation), and memmove (forward + backward overlap, identity).
/// Panics on any failure. Boot-time only — hot paths must not call
/// this from real workloads.
void StringSelfTest();

} // namespace duetos::core
