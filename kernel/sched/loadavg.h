#pragma once

#include "util/types.h"

/*
 * DuetOS — Linux-style 1/5/15-minute load averages.
 *
 * Three exponentially-weighted moving averages of the runnable-task
 * count, sampled at 5-second intervals from the scheduler tick
 * handler. Stored in Q11 fixed-point (1.0 == 1 << 11 == 2048) so
 * the math is one 64-bit multiply + one shift per EWMA step.
 *
 * The sample input is "tasks in the Running or Ready state right
 * now, excluding the idle task" — same interpretation `top` /
 * `uptime` use on Linux. Sleeping / blocked tasks don't contribute,
 * so a system that's idle reports load near 0.0 even with hundreds
 * of waiting tasks.
 *
 * The decay constants come from the classic Linux kernel.h
 * formulas:
 *   EXP_n = round(2048 * exp(-5 / (n*60))), n in {1, 5, 15} minutes
 * giving 1884 / 2014 / 2037 — the "amount of the previous average
 * to keep" per 5-second sample.
 */

namespace duetos::sched
{

/// Apply one EWMA step using the given runnable-task count.
/// Caller is responsible for spacing samples — typical use is once
/// every 5 seconds from the scheduler tick handler. Updating more
/// frequently is harmless but skews the time scale.
void LoadavgUpdate(u32 runnable);

/// Snapshot the three smoothed values. Output is Q11 fixed-point
/// (1.0 == 2048). Reads are atomic per word; values from different
/// update epochs may interleave by one sample but each individual
/// value is whole. nullptr arguments are ignored.
void LoadavgSnapshot(u32* one_min, u32* five_min, u32* fifteen_min);

/// Format a Q11 fixed-point load value as "X.YY" decimal into a
/// caller-provided buffer. 8 bytes is enough for any value < 1000.
/// Returns the number of characters written, excluding the NUL.
u32 LoadavgFormat(char* buf, u32 buflen, u32 fp);

} // namespace duetos::sched
