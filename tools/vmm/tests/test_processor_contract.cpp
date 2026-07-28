#include "test_main.h"

#include "processor_contract.h"

TEST(guest_cpu_contract_advertises_only_hypervisor_presence)
{
    const auto features = duetos::vmm::MakeSyntheticProcessorFeatures();

    CHECK_EQ(features.BanksCount, 1u);
    CHECK_EQ(features.Bank0.HypervisorPresent, 1u);
    CHECK_EQ(features.Bank0.AsUINT64, 1ull);
}
