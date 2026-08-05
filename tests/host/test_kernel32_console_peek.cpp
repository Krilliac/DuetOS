// test_kernel32_console_peek.cpp — hosted unit test for the pure
// counting / chunk-sizing helpers behind the SYS_STDIN_PEEK (231)
// wiring of the kernel32 console-input surface.
//
// Covers: userland/libs/kernel32/kernel32_console_input.h
//   (duetos_console_prospective_events — record-queue + kernel-ring
//    KEY_EVENT counting with probe-failure degradation and DWORD
//    saturation; duetos_console_drain_chunk — never-blocking drain
//    sizing bounded by record-ring space, probed bytes and scratch
//    capacity).

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/kernel32_console_input.h"

int main()
{
    // ---- duetos_console_prospective_events ----

    // Plain combinations: 2 prospective records per kernel byte.
    EXPECT_EQ(duetos_console_prospective_events(0u, 0LL), 0u);
    EXPECT_EQ(duetos_console_prospective_events(5u, 0LL), 5u);
    EXPECT_EQ(duetos_console_prospective_events(0u, 3LL), 6u);
    EXPECT_EQ(duetos_console_prospective_events(4u, 10LL), 24u);

    // Negative probe result (bad parameter / -ENOSYS while the
    // dispatch line is unwired) contributes zero — callers degrade
    // to the already-drained-only count.
    EXPECT_EQ(duetos_console_prospective_events(7u, -1LL), 7u);
    EXPECT_EQ(duetos_console_prospective_events(0u, -38LL), 0u);

    // Saturation at DWORD max instead of wrap.
    EXPECT_EQ(duetos_console_prospective_events(0xFFFFFFFFu, 1LL), 0xFFFFFFFFu);
    EXPECT_EQ(duetos_console_prospective_events(0u, 0x80000000LL), 0xFFFFFFFFu);
    EXPECT_EQ(duetos_console_prospective_events(10u, 0x100000000LL), 0xFFFFFFFFu);

    // ---- duetos_console_drain_chunk ----

    // Nothing to drain: no probed bytes, failed probe, no room for a
    // whole down+up pair, or no scratch space.
    EXPECT_EQ(duetos_console_drain_chunk(64u, 0LL, 200u), 0u);
    EXPECT_EQ(duetos_console_drain_chunk(64u, -1LL, 200u), 0u);
    EXPECT_EQ(duetos_console_drain_chunk(64u, -38LL, 200u), 0u);
    EXPECT_EQ(duetos_console_drain_chunk(0u, 100LL, 200u), 0u);
    EXPECT_EQ(duetos_console_drain_chunk(1u, 100LL, 200u), 0u);
    EXPECT_EQ(duetos_console_drain_chunk(64u, 100LL, 0u), 0u);

    // Record-ring space limits: 2 record slots per byte, odd free
    // counts round down.
    EXPECT_EQ(duetos_console_drain_chunk(64u, 100LL, 200u), 32u);
    EXPECT_EQ(duetos_console_drain_chunk(10u, 100LL, 200u), 5u);
    EXPECT_EQ(duetos_console_drain_chunk(7u, 100LL, 200u), 3u);
    EXPECT_EQ(duetos_console_drain_chunk(3u, 100LL, 200u), 1u);
    EXPECT_EQ(duetos_console_drain_chunk(2u, 100LL, 200u), 1u);

    // Probed-byte limit: never request more than the probe reported,
    // so the (normally blocking) read cannot block.
    EXPECT_EQ(duetos_console_drain_chunk(64u, 4LL, 200u), 4u);
    EXPECT_EQ(duetos_console_drain_chunk(64u, 1LL, 200u), 1u);

    // Scratch-buffer limit.
    EXPECT_EQ(duetos_console_drain_chunk(200u, 150LL, 32u), 32u);

    // Combined: the smallest bound wins.
    EXPECT_EQ(duetos_console_drain_chunk(6u, 2LL, 1u), 1u);

    return duetos_host_test::finish_main("kernel32_console_peek");
}
