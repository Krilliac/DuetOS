#include "drivers/net/iwlwifi_rings.h"

#include "core/panic.h"
#include "log/klog.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;

void Mmio32Write(const NicInfo& n, u32 off, u32 v)
{
    if (n.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off) = v;
    diag::Record(diag::Layer::Rings, "csr-w", off, v, 0, 0, "iwl");
}

[[maybe_unused]] u32 Mmio32Read(const NicInfo& n, u32 off)
{
    if (n.mmio_virt == nullptr)
        return 0xFFFFFFFFu;
    const u32 v = *reinterpret_cast<volatile u32*>(static_cast<u8*>(n.mmio_virt) + off);
    diag::Record(diag::Layer::Rings, "csr-r", off, v, 0, 0, "iwl");
    return v;
}

} // namespace

::duetos::core::Result<void> IwlRingsInit(NicInfo& n, IwlRingState* state)
{
    KLOG_TRACE_SCOPE("drivers/net/iwlwifi_rings", "IwlRingsInit");
    if (state == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "Init: null state pointer");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    *state = {};
    KLOG_INFO_A2V(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "rings init", "tx_queues",
                  static_cast<::duetos::u64>(kIwlNumTxQueues), "tx_ring_size",
                  static_cast<::duetos::u64>(kIwlTxRingSize));
    diag::RecordOk(diag::Layer::Rings, "init-start", kIwlNumTxQueues, kIwlTxRingSize, kIwlRxRingSize);

    for (u32 q = 0; q < kIwlNumTxQueues; ++q)
    {
        state->tx_queues[q].queue_id = q;
        state->tx_queues[q].size = kIwlTxRingSize;
        state->tx_queues[q].entry_bytes = kIwlTfdBytes;
        state->tx_queues[q].head = 0;
        state->tx_queues[q].tail = 0;
        state->tx_queues[q].dma_addr = 0;
        state->tx_queues[q].virt_base = nullptr;
        diag::RecordOk(diag::Layer::Rings, "tx-queue-init", q, kIwlTxRingSize, 0);
        // v0: no DMA arena yet — record intent.
        diag::RecordErr(diag::Layer::Rings, "tx-need-dma", static_cast<u32>(::duetos::core::ErrorCode::Unsupported), q,
                        kIwlTxRingSize * kIwlTfdBytes, 0);
    }

    state->rx_ring.size = kIwlRxRingSize;
    state->rx_ring.entry_bytes = kIwlRbdBytes;
    state->rx_ring.dma_addr = 0;
    state->rx_ring.virt_base = nullptr;
    diag::RecordErr(diag::Layer::Rings, "rx-need-dma", static_cast<u32>(::duetos::core::ErrorCode::Unsupported),
                    kIwlRxRingSize * kIwlRbdBytes, 0, 0);

    // Program FH base registers — these are no-ops with dma_addr = 0
    // but the writes are recorded so a hardware-side bring-up can
    // see what the driver intended.
    Mmio32Write(n, kFhTfdbBaseLow, 0);
    Mmio32Write(n, kFhTfdbBaseHigh, 0);
    Mmio32Write(n, kFhRscsrChnl0Rbdcb, 0);
    Mmio32Write(n, kFhRscsrChnl0Sbrb, 0);
    Mmio32Write(n, kFhRscsrChnl0Wptr, 0);

    state->initialized = true;
    KLOG_ONCE_WARN("drivers/net/iwlwifi_rings",
                   "rings init: DMA arena not yet provided — TX/RX disabled until kCapDma");
    diag::RecordOk(diag::Layer::Rings, "init-done", 0, 0, 0);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> IwlRingsTeardown(NicInfo& n, IwlRingState* state)
{
    if (state == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "Teardown: null state pointer");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "rings teardown");
    diag::RecordOk(diag::Layer::Rings, "teardown", 0, 0, 0);
    Mmio32Write(n, kFhRscsrChnl0Wptr, 0);
    Mmio32Write(n, kFhTcsrChnlTxConfig, 0);
    state->initialized = false;
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> IwlRingsSubmitTx(NicInfo& n, IwlRingState* state, u32 queue_id, const u8* frame,
                                              u32 frame_len)
{
    (void)n;
    if (state == nullptr || queue_id >= kIwlNumTxQueues || frame == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "SubmitTx: bad args; queue_id",
                     static_cast<u64>(queue_id));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if (!state->initialized)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings", "SubmitTx: rings not initialized");
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }

    IwlTxRing& q = state->tx_queues[queue_id];
    diag::RecordOk(diag::Layer::Tx, "tx-submit-intent", queue_id, frame_len, q.head);
    ++q.doorbell_count;
    // v0 cannot copy bytes into the (non-existent) TFD. Record the
    // intent + return Unsupported so callers know the frame was
    // dropped.
    diag::RecordErr(diag::Layer::Tx, "tx-need-dma", static_cast<u32>(::duetos::core::ErrorCode::Unsupported), queue_id,
                    frame_len, 0);
    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

u32 IwlRingsServiceRx(NicInfo& n, IwlRingState* state)
{
    (void)n;
    if (state == nullptr || !state->initialized)
        return 0;
    // Without DMA pointers the ring is empty. Record one
    // service-cycle event and return 0.
    diag::RecordOk(diag::Layer::Rx, "rx-service-empty", 0, 0, 0);
    ++state->rx_ring.ring_advance_count;
    return 0;
}

void IwlRingsSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/net/iwlwifi_rings", "IwlRingsSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings",
                "self-test: init/submit/teardown without DMA arena");
    NicInfo n{};
    n.mmio_virt = nullptr;
    IwlRingState s{};
    auto ir = IwlRingsInit(n, &s);
    KASSERT(ir.has_value(), "drivers/net/iwlwifi_rings", "rings-init failed");
    KASSERT(s.initialized, "drivers/net/iwlwifi_rings", "rings.initialized=false after init");
    KASSERT(s.tx_queues[0].size == kIwlTxRingSize, "drivers/net/iwlwifi_rings", "tx ring size wrong");
    KASSERT(s.rx_ring.size == kIwlRxRingSize, "drivers/net/iwlwifi_rings", "rx ring size wrong");

    const u8 dummy[16] = {};
    auto sr = IwlRingsSubmitTx(n, &s, 0, dummy, sizeof(dummy));
    KASSERT(!sr.has_value(), "drivers/net/iwlwifi_rings", "submit must fail without DMA");

    KASSERT(IwlRingsServiceRx(n, &s) == 0, "drivers/net/iwlwifi_rings", "rx service should be empty");
    auto tr = IwlRingsTeardown(n, &s);
    KASSERT(tr.has_value(), "drivers/net/iwlwifi_rings", "teardown failed");
    KASSERT(!s.initialized, "drivers/net/iwlwifi_rings", "rings.initialized=true after teardown");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings",
                "self-test OK (init + submit-without-DMA + teardown verified)");
}

} // namespace duetos::drivers::net
