#include "test_main.h"

TEST(smoke_runner_works)
{
    CHECK(1 + 1 == 2);
    CHECK_EQ(42, 40 + 2);
}
