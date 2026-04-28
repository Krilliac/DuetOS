#pragma once

// host_test_helper.h — minimal ASSERT framework for tests/host/.
//
// Each test_*.cpp defines `int main()` and uses `EXPECT_*` /
// `ASSERT_*` macros to check invariants. A failed assertion prints
// `<file>:<line>: FAIL: <message>` and increments a counter; main
// returns the counter (so CTest reports failure on any miss).
//
// Why not gtest / Catch2: those are large dependencies whose value
// scales with test volume. The tests/host/ tree at v0 has a handful
// of tiny tests; rolling our own keeps the build self-contained and
// the failure output one greppable line per failed expectation.

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace duetos_host_test
{

inline int& failure_count()
{
    static int n = 0;
    return n;
}

inline int finish_main(const char* test_name)
{
    const int n = failure_count();
    if (n == 0)
    {
        std::printf("PASS: %s\n", test_name);
        return 0;
    }
    std::printf("FAIL: %s (%d expectation(s) failed)\n", test_name, n);
    return 1;
}

} // namespace duetos_host_test

// EXPECT_*: record failure but keep running. Use for independent
// checks within one test where you want to see all failures.
#define EXPECT_TRUE(cond)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: EXPECT_TRUE(%s)\n", __FILE__, __LINE__, #cond);                         \
            ++::duetos_host_test::failure_count();                                                                     \
        }                                                                                                              \
    } while (0)

#define EXPECT_FALSE(cond)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((cond))                                                                                                    \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: EXPECT_FALSE(%s)\n", __FILE__, __LINE__, #cond);                        \
            ++::duetos_host_test::failure_count();                                                                     \
        }                                                                                                              \
    } while (0)

#define EXPECT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto _ea = (a);                                                                                          \
        const auto _eb = (b);                                                                                          \
        if (!(_ea == _eb))                                                                                             \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: EXPECT_EQ(%s, %s)\n", __FILE__, __LINE__, #a, #b);                      \
            ++::duetos_host_test::failure_count();                                                                     \
        }                                                                                                              \
    } while (0)

#define EXPECT_NE(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto _ea = (a);                                                                                          \
        const auto _eb = (b);                                                                                          \
        if ((_ea == _eb))                                                                                              \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: EXPECT_NE(%s, %s)\n", __FILE__, __LINE__, #a, #b);                      \
            ++::duetos_host_test::failure_count();                                                                     \
        }                                                                                                              \
    } while (0)

#define EXPECT_STREQ(a, b)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        const char* _ea = (a);                                                                                         \
        const char* _eb = (b);                                                                                         \
        if (_ea == nullptr || _eb == nullptr || std::strcmp(_ea, _eb) != 0)                                            \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FAIL: EXPECT_STREQ(%s, %s) — got \"%s\" vs \"%s\"\n", __FILE__, __LINE__, #a, \
                         #b, _ea ? _ea : "(null)", _eb ? _eb : "(null)");                                              \
            ++::duetos_host_test::failure_count();                                                                     \
        }                                                                                                              \
    } while (0)

// ASSERT_*: like EXPECT_*, but abort the test on first failure.
// Use only when subsequent checks would crash on the bad value.
#define ASSERT_TRUE(cond)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FATAL: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #cond);                        \
            ++::duetos_host_test::failure_count();                                                                     \
            return ::duetos_host_test::finish_main(__FILE__);                                                          \
        }                                                                                                              \
    } while (0)
