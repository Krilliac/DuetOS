#include "drivers/net/iwlwifi_rings.h"

#include "core/panic.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::drivers::net
{

namespace
{

namespace diag = duetos::net::wireless::diag;
namespace mm = duetos::mm;

// Per-queue DMA buffers. One pool slot per (TX queue, RX ring) so
// the bookkeeping stays inside the TU — the public IwlRingState
// only carries the device-visible phys + the kernel-VA virt the
// driver code reads/writes through (already matches the existing
// IwlTxRing / IwlRxRing fields).
struct DmaSlot
{
    mm::DmaBuffer buf;
    bool live;
};
constinit DmaSlot g_tx_dma[kIwlNumTxQueues] = {};
constinit DmaSlot g_rx_dma = {};

// RX data-buffer pool. The RBD ring itself only carries 256 ×
// 8-byte phys-addr descriptors; each descriptor points at a 4 KiB
// buffer the chip writes received frames into. We allocate the
// pool as one contiguous 1 MiB run so the per-buffer phys addrs
// are deterministic (pool_base + 4 KiB × i) and the driver doesn't
// need to track a list of independent allocations.
inline constexpr u32 kRxDataBufBytes = 4096;
constinit DmaSlot g_rx_data_dma = {};

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

void FreeAllRings()
{
    for (u32 q = 0; q < kIwlNumTxQueues; ++q)
    {
        if (g_tx_dma[q].live)
        {
            mm::FreeDmaCoherent(g_tx_dma[q].buf);
            g_tx_dma[q] = {};
        }
    }
    if (g_rx_dma.live)
    {
        mm::FreeDmaCoherent(g_rx_dma.buf);
        g_rx_dma = {};
    }
    if (g_rx_data_dma.live)
    {
        mm::FreeDmaCoherent(g_rx_data_dma.buf);
        g_rx_data_dma = {};
    }
}

// Populate the RBD ring with one phys-addr per slot pointing into
// the contiguous data-buffer pool. Modern iwlwifi (7000-series and
// later) treats each RBD as a 64-bit physical address; legacy
// chips use a 32-bit-shifted-by-8 form. v0 writes 64-bit and
// captures the legacy variant as a GAP — every chip in the
// supported matrix is 7000-series+.
// GAP: legacy < 7000-series RBD format (32-bit, shifted 8).
void PopulateRbdRing(IwlRxRing& rx, mm::PhysAddr data_pool_base)
{
    auto* rbd = static_cast<volatile u64*>(rx.virt_base);
    for (u32 i = 0; i < rx.size; ++i)
        rbd[i] = data_pool_base + static_cast<u64>(i) * kRxDataBufBytes;
    mm::DmaBuffer tmp{0, rx.virt_base, static_cast<u64>(rx.size) * kIwlRbdBytes, mm::Zone::Dma32};
    mm::DmaSyncForDevice(tmp, 0, tmp.bytes);
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

    // Every iwlwifi chip in the supported matrix is 32-bit DMA-
    // capable for the descriptor rings (the data buffers can be
    // 64-bit on newer parts but the descriptors themselves still
    // expect <4 GiB physical addresses). Dma32 is the right zone.
    const mm::Zone kRingZone = mm::Zone::Dma32;

    // TX rings: each queue gets a 256-entry × 128 B = 32 KiB ring.
    const u64 kTxBytes = static_cast<u64>(kIwlTxRingSize) * kIwlTfdBytes;
    for (u32 q = 0; q < kIwlNumTxQueues; ++q)
    {
        auto r = mm::AllocDmaCoherent(kTxBytes, kRingZone);
        if (!r.has_value())
        {
            diag::RecordErr(diag::Layer::Rings, "tx-dma-fail", static_cast<u32>(r.error()), q,
                            static_cast<u32>(kTxBytes), 0);
            FreeAllRings();
            return ::duetos::core::Err{r.error()};
        }
        g_tx_dma[q] = {r.value(), true};
        state->tx_queues[q].queue_id = q;
        state->tx_queues[q].size = kIwlTxRingSize;
        state->tx_queues[q].entry_bytes = kIwlTfdBytes;
        state->tx_queues[q].head = 0;
        state->tx_queues[q].tail = 0;
        state->tx_queues[q].dma_addr = r.value().phys;
        state->tx_queues[q].virt_base = r.value().virt;
        diag::RecordOk(diag::Layer::Rings, "tx-dma-allocated", q, static_cast<u32>(kTxBytes),
                       static_cast<u32>(r.value().phys));
    }

    // RX descriptor ring: 256-entry × 8 B = 2 KiB.
    {
        const u64 kRxBytes = static_cast<u64>(kIwlRxRingSize) * kIwlRbdBytes;
        auto r = mm::AllocDmaCoherent(kRxBytes, kRingZone);
        if (!r.has_value())
        {
            diag::RecordErr(diag::Layer::Rings, "rx-dma-fail", static_cast<u32>(r.error()), static_cast<u32>(kRxBytes),
                            0, 0);
            FreeAllRings();
            return ::duetos::core::Err{r.error()};
        }
        g_rx_dma = {r.value(), true};
        state->rx_ring.size = kIwlRxRingSize;
        state->rx_ring.entry_bytes = kIwlRbdBytes;
        state->rx_ring.dma_addr = r.value().phys;
        state->rx_ring.virt_base = r.value().virt;
        diag::RecordOk(diag::Layer::Rings, "rx-dma-allocated", static_cast<u32>(kRxBytes),
                       static_cast<u32>(r.value().phys), 0);
    }

    // RX data-buffer pool: one contiguous 1 MiB Dma32 run carved
    // into 256 × 4 KiB slots (slot i lives at pool_base + 4 KiB·i).
    // Each RBD entry is populated with the per-slot phys addr;
    // the chip writes received frames into the slot pointed to by
    // RBD[read_index] then advances. The driver hands buffers back
    // to the chip by re-publishing them and bumping the write
    // pointer. v0 hands all 256 to the chip up-front.
    {
        const u64 kPoolBytes = static_cast<u64>(kIwlRxRingSize) * kRxDataBufBytes;
        auto r = mm::AllocDmaCoherent(kPoolBytes, kRingZone);
        if (!r.has_value())
        {
            diag::RecordErr(diag::Layer::Rings, "rx-data-pool-fail", static_cast<u32>(r.error()),
                            static_cast<u32>(kPoolBytes), 0, 0);
            FreeAllRings();
            return ::duetos::core::Err{r.error()};
        }
        g_rx_data_dma = {r.value(), true};
        diag::RecordOk(diag::Layer::Rings, "rx-data-pool-allocated", static_cast<u32>(kPoolBytes),
                       static_cast<u32>(r.value().phys), 0);
        PopulateRbdRing(state->rx_ring, r.value().phys);
    }

    // Program FH base registers with the real ring 0 physical
    // addresses (queue 0 is the command queue). Other queues are
    // mapped via per-queue base regs that don't exist as constants
    // in this file yet — wiring them up is part of the per-vendor
    // bring-up slice that consumes this DMA.
    const u64 tfd0 = state->tx_queues[0].dma_addr;
    Mmio32Write(n, kFhTfdbBaseLow, static_cast<u32>(tfd0 & 0xFFFFFFFFu));
    Mmio32Write(n, kFhTfdbBaseHigh, static_cast<u32>(tfd0 >> 32));
    Mmio32Write(n, kFhRscsrChnl0Rbdcb, static_cast<u32>(state->rx_ring.dma_addr & 0xFFFFFFFFu));
    Mmio32Write(n, kFhRscsrChnl0Sbrb, 0);
    // Advance the RX write pointer to (size - 1) so the chip sees
    // every RBD slot as ready-to-fill. Read pointer starts at 0;
    // hardware advances it as it fills slots, then the driver bumps
    // the write pointer past the position it has finished
    // processing. v0 publishes all 256 up-front and the bottom-half
    // (when it lands) re-publishes one slot at a time.
    Mmio32Write(n, kFhRscsrChnl0Wptr, kIwlRxRingSize - 1);
    state->rx_ring.read_index = 0;

    state->initialized = true;
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
    FreeAllRings();
    for (u32 q = 0; q < kIwlNumTxQueues; ++q)
    {
        state->tx_queues[q].dma_addr = 0;
        state->tx_queues[q].virt_base = nullptr;
    }
    state->rx_ring.dma_addr = 0;
    state->rx_ring.virt_base = nullptr;
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
                "self-test: init + DMA-coherent ring alloc + teardown");
    NicInfo n{};
    n.mmio_virt = nullptr;
    IwlRingState s{};
    auto ir = IwlRingsInit(n, &s);
    KASSERT(ir.has_value(), "drivers/net/iwlwifi_rings", "rings-init failed");
    KASSERT(s.initialized, "drivers/net/iwlwifi_rings", "rings.initialized=false after init");
    KASSERT(s.tx_queues[0].size == kIwlTxRingSize, "drivers/net/iwlwifi_rings", "tx ring size wrong");
    KASSERT(s.rx_ring.size == kIwlRxRingSize, "drivers/net/iwlwifi_rings", "rx ring size wrong");
    // DMA buffers must actually be live now (was: 0/null until the
    // mm::AllocDmaCoherent slice landed).
    KASSERT(s.tx_queues[0].dma_addr != 0, "drivers/net/iwlwifi_rings", "tx[0] dma_addr=0 after init");
    KASSERT(s.tx_queues[0].virt_base != nullptr, "drivers/net/iwlwifi_rings", "tx[0] virt_base=null after init");
    KASSERT(s.rx_ring.dma_addr != 0, "drivers/net/iwlwifi_rings", "rx dma_addr=0 after init");
    KASSERT(s.rx_ring.virt_base != nullptr, "drivers/net/iwlwifi_rings", "rx virt_base=null after init");
    // Dma32 zone ceiling: every ring base must be <4 GiB so the
    // chip's 32-bit descriptor-pointer registers can address it.
    KASSERT(s.tx_queues[0].dma_addr < (4ULL * 1024 * 1024 * 1024), "drivers/net/iwlwifi_rings",
            "tx[0] phys above Dma32 ceiling");
    KASSERT(s.rx_ring.dma_addr < (4ULL * 1024 * 1024 * 1024), "drivers/net/iwlwifi_rings",
            "rx phys above Dma32 ceiling");

    const u8 dummy[16] = {};
    auto sr = IwlRingsSubmitTx(n, &s, 0, dummy, sizeof(dummy));
    // SubmitTx still returns Unsupported until the TFD descriptor-
    // build + doorbell-program slice lands (separate from this one).
    KASSERT(!sr.has_value(), "drivers/net/iwlwifi_rings", "submit must fail until TFD-build lands");

    KASSERT(IwlRingsServiceRx(n, &s) == 0, "drivers/net/iwlwifi_rings", "rx service should be empty");

    // RBD ring populated with monotonically-increasing buffer phys
    // addrs over a contiguous 1 MiB pool. RBD[i] - RBD[0] should be
    // exactly i × 4 KiB.
    {
        auto* rbd = static_cast<volatile u64*>(s.rx_ring.virt_base);
        const u64 base = rbd[0];
        KASSERT(base != 0, "drivers/net/iwlwifi_rings", "rbd[0] not populated");
        KASSERT(rbd[1] == base + kRxDataBufBytes, "drivers/net/iwlwifi_rings", "rbd[1] not contiguous with rbd[0]");
        KASSERT(rbd[kIwlRxRingSize - 1] == base + (kIwlRxRingSize - 1) * static_cast<u64>(kRxDataBufBytes),
                "drivers/net/iwlwifi_rings", "rbd[last] phys mismatch");
    }

    auto tr = IwlRingsTeardown(n, &s);
    KASSERT(tr.has_value(), "drivers/net/iwlwifi_rings", "teardown failed");
    KASSERT(!s.initialized, "drivers/net/iwlwifi_rings", "rings.initialized=true after teardown");
    KASSERT(s.tx_queues[0].dma_addr == 0, "drivers/net/iwlwifi_rings", "tx[0] dma_addr leaked after teardown");
    KASSERT(s.rx_ring.dma_addr == 0, "drivers/net/iwlwifi_rings", "rx dma_addr leaked after teardown");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "drivers/net/iwlwifi_rings",
                "self-test OK (init + DMA + RBD pool + Dma32 ceiling + teardown verified)");
}

} // namespace duetos::drivers::net
