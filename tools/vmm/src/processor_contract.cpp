#include "processor_contract.h"

namespace duetos::vmm
{

WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS MakeSyntheticProcessorFeatures()
{
    static_assert(WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS_COUNT == 1);

    WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS features = {};
    features.BanksCount = WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS_COUNT;
    features.Bank0.HypervisorPresent = 1;
    return features;
}

} // namespace duetos::vmm
