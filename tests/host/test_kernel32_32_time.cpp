// test_kernel32_32_time.cpp — hosted unit test for the
// QueryPerformanceCounter epoch extension used by the i386 (PE32)
// kernel32 companion.
//
// Covers:
//   userland/libs/kernel32_32/kernel32_32_qpc.h (Duet32QpcExtend)
//
// Why this is worth pinning. The i386 syscall return path is 32 bits
// wide: kernel/arch/x86_64/exceptions.S hands a compat-mode caller
// back only eax, so SYS_NOW_NS's 64-bit nanosecond counter arrives
// truncated and rolls over every 2^32 ns (~4.295 s). Returning that
// raw value as QueryPerformanceCounter would make elapsed deltas go
// NEGATIVE several times a minute — the one thing every QPC caller
// assumes cannot happen. Duet32QpcExtend rebuilds the high half in
// user space; the properties asserted below are exactly the ones a
// caller relies on:
//
//   1. monotonic — a later sample never reads lower than an earlier
//      one, across any number of wraps;
//   2. exact — while the caller polls faster than the wrap period,
//      the reconstructed value is the true counter;
//   3. equality is not a wrap — two samples inside the same
//      nanosecond must not jump a whole epoch.

#include "host_test_helper.h"

#include "../../userland/libs/kernel32_32/kernel32_32_qpc.h"

using namespace duetos_host_test;

namespace
{

constexpr unsigned long long kWrap = 0x1'0000'0000ULL;

} // namespace

int main()
{
    // ---- Property 3 first: it is the easiest to get wrong. --------
    {
        Duet32QpcState st{};
        EXPECT_EQ(Duet32QpcExtend(&st, 5000u), 5000ull);
        // Same nanosecond sampled twice: same answer, no epoch bump.
        EXPECT_EQ(Duet32QpcExtend(&st, 5000u), 5000ull);
        EXPECT_EQ(st.epoch, 0u);
    }

    // ---- Property 2: exact while polling inside one epoch. --------
    {
        Duet32QpcState st{};
        Duet32QpcExtend(&st, 100u);
        EXPECT_EQ(Duet32QpcExtend(&st, 200u), 200ull);
        EXPECT_EQ(Duet32QpcExtend(&st, 0xFFFF'FFFFu), 0xFFFF'FFFFull);
        EXPECT_EQ(st.epoch, 0u);
    }

    // ---- A single wrap adds exactly 2^32, not 2^32 +/- anything. --
    {
        Duet32QpcState st{};
        Duet32QpcExtend(&st, 0xFFFF'FF00u);
        // Counter rolled over and advanced 0x200 ns past the boundary.
        const unsigned long long after = Duet32QpcExtend(&st, 0x0000'0100u);
        EXPECT_EQ(after, kWrap + 0x100ull);
        EXPECT_EQ(st.epoch, 1u);
        // The delta across the wrap is the true elapsed nanoseconds.
        EXPECT_EQ(after - 0xFFFF'FF00ull, 0x200ull);
    }

    // ---- Property 1: monotonic across many wraps. -----------------
    {
        Duet32QpcState st{};
        unsigned long long prev = Duet32QpcExtend(&st, 0u);
        unsigned int low = 0;
        // Step by an amount that does not divide 2^32 evenly, so the
        // wrap lands at a different offset each time round.
        const unsigned int kStep = 0x3333'3333u;
        for (int i = 0; i < 64; ++i)
        {
            low += kStep;
            const unsigned long long now = Duet32QpcExtend(&st, low);
            EXPECT_TRUE(now > prev);
            // Every step advances by exactly kStep once the epoch is
            // folded back in — that is the whole point of the fixup.
            EXPECT_EQ(now - prev, static_cast<unsigned long long>(kStep));
            prev = now;
        }
        // 64 steps of 0x33333333 span 0x33333333 * 64 ns; that many
        // wraps must have been observed.
        EXPECT_EQ(prev, static_cast<unsigned long long>(kStep) * 64ull);
    }

    // ---- A NULL state degrades to the raw low word, never a crash.
    {
        EXPECT_EQ(Duet32QpcExtend(nullptr, 0xDEAD'BEEFu), 0xDEAD'BEEFull);
    }

    return duetos_host_test::finish_main("kernel32_32_time");
}
