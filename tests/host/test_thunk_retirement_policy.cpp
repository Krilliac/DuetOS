// Hosted tests for the fail-closed Win32 thunk-retirement policy.
//
// Including the policy's X-macro manifest here proves that the loader
// deny list and the build-gated DLL export list cannot drift apart.

#include "host_test_helper.h"
#include "subsystems/win32/thunk_retirement_policy.h"

using duetos::win32::IsRetiredKernel32ImportName;
using duetos::win32::kRetiredKernel32Imports;
using duetos::win32::ThunkRetirementRequiresRealDll;

int main()
{
    unsigned count = 0;
    for (const char* name : kRetiredKernel32Imports)
    {
        ++count;
        EXPECT_TRUE(ThunkRetirementRequiresRealDll("kernel32.dll", name));
        EXPECT_TRUE(ThunkRetirementRequiresRealDll("KERNEL32.DLL", name));
        EXPECT_TRUE(ThunkRetirementRequiresRealDll("kernel32", name));
        EXPECT_TRUE(ThunkRetirementRequiresRealDll("kernelbase.dll", name));
        EXPECT_TRUE(IsRetiredKernel32ImportName(name));
    }
    EXPECT_EQ(count, 4u);

    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", "createthread"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", "CreateThreadEx"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernelbase.dll", "CreateThreadEx"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll(nullptr, "CreateThread"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", nullptr));
    EXPECT_FALSE(IsRetiredKernel32ImportName(nullptr));

    return duetos_host_test::finish_main("thunk_retirement_policy");
}
