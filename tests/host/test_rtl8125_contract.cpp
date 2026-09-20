#include "host_test_helper.h"

#include "drivers/net/rtl8125_contract.h"

using namespace duetos::drivers::net::rtl8125::contract;

int main()
{
    EXPECT_TRUE(IsExactHardware(0x10EC, 0x8125, 0x10EC, 0x0123, 0x05));
    EXPECT_FALSE(IsExactHardware(0x10EC, 0x8125, 0x10EC, 0x0123, 0x04));
    EXPECT_FALSE(IsExactHardware(0x10EC, 0x8125, 0x10EC, 0x9999, 0x05));

    EXPECT_EQ(EncodeTx(0x12345000, 1500, true, true, false), 0x30000000u | 1500u);
    EXPECT_EQ(EncodeRx(0x12345000, 16383, true), 0xC0003FFFu);
    EXPECT_FALSE(EncodeRx(0x12345003, 16383, false) != 0);
    EXPECT_TRUE(DescriptorAddressValid(0x12345000, 0x100000));
    EXPECT_FALSE(DescriptorAddressValid(0x12345003, 0x100000));

    EXPECT_EQ(ValidateRx(0, 0, 0x1000), RxDisposition::Drop);
    EXPECT_EQ(ValidateRx(kDescOwn, 64, 0x1000), RxDisposition::NotReady);
    EXPECT_EQ(ValidateRx(kDescFirst | kDescLast, 64, 0x1000), RxDisposition::Deliver);
    EXPECT_EQ(ValidateRx(kDescFirst | kDescLast | kRxCrcError, 64, 0x1000), RxDisposition::Drop);
    EXPECT_EQ(ValidateRx(kDescFirst | kDescLast, 0, 0x1000), RxDisposition::Drop);
    EXPECT_EQ(ValidateRx(kDescFirst | kDescLast, 16000, 0x1000), RxDisposition::Drop);
    EXPECT_EQ(RxPayloadLength(64), 60);
    EXPECT_EQ(RxPayloadLength(60), 0);

    TxCursor tx{};
    EXPECT_TRUE(TxPublish(tx));
    EXPECT_EQ(tx.in_flight, 1u);
    EXPECT_TRUE(TxReclaim(tx, true));
    EXPECT_EQ(tx.in_flight, 0u);
    EXPECT_FALSE(TxReclaim(tx, true));

    EXPECT_TRUE(TxPublish(tx));
    EXPECT_TRUE(TxReclaimAfterCpuSync(tx, true, true));
    EXPECT_TRUE(TxPublish(tx));
    EXPECT_FALSE(TxReclaimAfterCpuSync(tx, false, true));

    AllocationPlan plan{};
    EXPECT_FALSE(AllocationRollback(plan, true, true, true, false));
    EXPECT_EQ(plan.live_allocations, 0u);

    TeardownState retained{};
    EXPECT_TRUE(TeardownStep(retained, TeardownAction::CloseOperations));
    EXPECT_FALSE(TeardownStep(retained, TeardownAction::DisableBusMaster));
    EXPECT_EQ(retained.completed, 1u);

    TeardownState teardown{};
    EXPECT_TRUE(TeardownStep(teardown, TeardownAction::CloseOperations));
    EXPECT_TRUE(TeardownStep(teardown, TeardownAction::JoinWorker));
    EXPECT_TRUE(TeardownStep(teardown, TeardownAction::DisableDatapath));
    EXPECT_TRUE(TeardownStep(teardown, TeardownAction::DisableBusMaster));
    EXPECT_TRUE(TeardownStep(teardown, TeardownAction::FreeDma));
    EXPECT_FALSE(TeardownStep(teardown, TeardownAction::FreeDma));
    return duetos_host_test::finish_main("rtl8125_contract");
}
