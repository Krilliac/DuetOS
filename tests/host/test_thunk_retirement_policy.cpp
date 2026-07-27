// Hosted tests for the fail-closed Win32 thunk-retirement policy.
//
// Including the policy's X-macro manifest here proves that the loader
// deny list and the build-gated DLL export list cannot drift apart.

#include "host_test_helper.h"
#include "subsystems/win32/thunk_retirement_policy.h"

using duetos::win32::IsRetiredKernel32ImportName;
using duetos::win32::kRetiredKernel32Imports;
using duetos::win32::RetiredNamedImportWouldFallBack;
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
    EXPECT_EQ(count, 14u);

    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", "createthread"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", "CreateThreadEx"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernelbase.dll", "CreateThreadEx"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("ntdll.dll", "GetLastError"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("api-ms-win-not-a-contract.dll", "GetLastError"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll(nullptr, "CreateThread"));
    EXPECT_FALSE(ThunkRetirementRequiresRealDll("kernel32.dll", nullptr));
    EXPECT_FALSE(IsRetiredKernel32ImportName(nullptr));

    EXPECT_TRUE(RetiredNamedImportWouldFallBack(false, false, false, "GetLastError"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(false, false, true, "GetLastError"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(true, false, false, "GetLastError"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(false, true, false, "GetLastError"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(false, false, false, "getlasterror"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(false, false, false, "GetLastErrorEx"));
    EXPECT_FALSE(RetiredNamedImportWouldFallBack(false, false, false, nullptr));

    return duetos_host_test::finish_main("thunk_retirement_policy");
}
