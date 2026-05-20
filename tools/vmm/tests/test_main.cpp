// Minimal no-dependency test runner. Each TEST() registers itself;
// main() runs all and reports. Keeps the VMM dependency-light (no
// gtest). A failing CHECK aborts the test with a nonzero exit.
#include "test_main.h"
#include <cstdio>
#include <vector>

namespace vmmtest
{
std::vector<Case>& Registry()
{
    static std::vector<Case> r;
    return r;
}
} // namespace vmmtest

int main()
{
    int failed = 0;
    for (auto& c : vmmtest::Registry())
    {
        try
        {
            c.fn();
            std::printf("[ PASS ] %s\n", c.name);
        }
        catch (const std::exception& e)
        {
            std::printf("[ FAIL ] %s : %s\n", c.name, e.what());
            ++failed;
        }
    }
    std::printf("%d test(s), %d failed\n",
                (int)vmmtest::Registry().size(), failed);
    return failed ? 1 : 0;
}
