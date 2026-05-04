#include "sched/loadavg.h"

namespace duetos::sched
{

namespace
{

// Q11 fixed-point: FIXED_1 == 1.0. Linux kernel.h ships at FSHIFT=11
// for the same reason — 11 fractional bits leaves 21 integer bits,
// plenty of headroom for runnable counts on any plausible machine
// without overflowing the u64 intermediate product.
constexpr u32 kFShift = 11;
constexpr u32 kFixed1 = 1u << kFShift;

// Decay factors — "fraction of the previous average to keep on each
// 5-second sample". Smaller value = faster decay.
//   EXP_1  = round(2048 * exp(-5/60))     == 1884   (1-min)
//   EXP_5  = round(2048 * exp(-5/300))    == 2014   (5-min)
//   EXP_15 = round(2048 * exp(-5/900))    == 2037   (15-min)
constexpr u32 kExp1 = 1884;
constexpr u32 kExp5 = 2014;
constexpr u32 kExp15 = 2037;

// The smoothed averages, in Q11 fixed-point. Word-sized writes are
// atomic on x86_64 — readers that catch a momentarily stale value
// just lag one sample.
volatile u32 g_load_1m = 0;
volatile u32 g_load_5m = 0;
volatile u32 g_load_15m = 0;

// EWMA step:
//   load' = round((load * exp_factor + active * (FIXED_1 - exp_factor)) / FIXED_1)
// where `active` is the runnable count promoted to fixed-point. The
// 64-bit intermediate covers any plausible (load * 2048) without
// truncation.
u32 calc_load(u32 prev, u32 exp_factor, u32 active_fixed)
{
    const u64 prev_term = static_cast<u64>(prev) * exp_factor;
    const u64 active_term = static_cast<u64>(active_fixed) * (kFixed1 - exp_factor);
    return static_cast<u32>((prev_term + active_term + (kFixed1 / 2)) >> kFShift);
}

} // namespace

void LoadavgUpdate(u32 runnable)
{
    const u32 active = runnable << kFShift;
    g_load_1m = calc_load(g_load_1m, kExp1, active);
    g_load_5m = calc_load(g_load_5m, kExp5, active);
    g_load_15m = calc_load(g_load_15m, kExp15, active);
}

void LoadavgSnapshot(u32* one_min, u32* five_min, u32* fifteen_min)
{
    if (one_min != nullptr)
    {
        *one_min = g_load_1m;
    }
    if (five_min != nullptr)
    {
        *five_min = g_load_5m;
    }
    if (fifteen_min != nullptr)
    {
        *fifteen_min = g_load_15m;
    }
}

u32 LoadavgFormat(char* buf, u32 buflen, u32 fp)
{
    if (buf == nullptr || buflen == 0)
    {
        return 0;
    }
    u32 whole = fp >> kFShift;
    u32 frac_q = fp & (kFixed1 - 1);
    // Round the fractional part to two decimal places. (frac/2048)*100.
    u32 frac_pct = (frac_q * 100u + (kFixed1 / 2)) / kFixed1;
    if (frac_pct == 100u)
    {
        ++whole;
        frac_pct = 0;
    }
    u32 n = 0;
    if (whole == 0)
    {
        if (n + 1 < buflen)
        {
            buf[n++] = '0';
        }
    }
    else
    {
        char tmp[12];
        u32 t = 0;
        while (whole > 0 && t < sizeof(tmp))
        {
            tmp[t++] = static_cast<char>('0' + (whole % 10));
            whole /= 10;
        }
        while (t > 0 && n + 1 < buflen)
        {
            buf[n++] = tmp[--t];
        }
    }
    if (n + 1 < buflen)
    {
        buf[n++] = '.';
    }
    if (n + 1 < buflen)
    {
        buf[n++] = static_cast<char>('0' + (frac_pct / 10));
    }
    if (n + 1 < buflen)
    {
        buf[n++] = static_cast<char>('0' + (frac_pct % 10));
    }
    if (n < buflen)
    {
        buf[n] = '\0';
    }
    return n;
}

} // namespace duetos::sched
