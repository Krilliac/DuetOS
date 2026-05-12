#pragma once

#include "drivers/net/net.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — iwlwifi TX (TFD) + RX (RBD) ring scaffolds.
 *
 * The iwlwifi TX queue is a Transmit Frame Descriptor (TFD) ring;
 * each entry is 128 bytes covering up to 20 scatter-gather DMA
 * fragments + control fields. The RX path is a Receive Buffer
 * Descriptor (RBD) ring of 64-bit DMA pointers.
 *
 * Layout per Linux iwlwifi/iwl-fh.h:
 *   TFD: 256-entry ring, 128 B/entry, 32 KiB total, 256-byte
 *        alignment.
 *   RBD: 256-entry ring, 8 B/entry (modern), 2 KiB total.
 *
 * v0 lays out the ring structures + records every doorbell write
 * to the diag ring, but does not actually allocate DMA-coherent
 * memory yet — that needs a `mm::AllocDmaCoherent` API which is
 * tracked separately. Real hardware bring-up will plug the DMA
 * arena in here.
 *
 * Heavy diag logging on every doorbell + every claimed-completion
 * is the core feature: this code ships untested.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kIwlTxRingSize = 256;
inline constexpr u32 kIwlRxRingSize = 256;
inline constexpr u32 kIwlTfdBytes = 128;
inline constexpr u32 kIwlRbdBytes = 8;
inline constexpr u32 kIwlNumTxQueues = 4; // command + 3 priority queues

// Flow Handler (FH) register offsets — TX / RX ring programming.
inline constexpr u32 kFhTfdbBaseLow = 0x1900;
inline constexpr u32 kFhTfdbBaseHigh = 0x1904;
inline constexpr u32 kFhTcsrChnlNumRb = 0x1A00;
inline constexpr u32 kFhTcsrChnlTxBuf = 0x1A04;
inline constexpr u32 kFhTcsrChnlTxConfig = 0x1A08;
inline constexpr u32 kFhRscsrChnl0Stts = 0x1B00;
inline constexpr u32 kFhRscsrChnl0Wptr = 0x1BC0;
inline constexpr u32 kFhRscsrChnl0Rbdcb = 0x1BC8;
inline constexpr u32 kFhRscsrChnl0Sbrb = 0x1BCC;

// HBUS target write-pointer register — the TX doorbell. Modern
// iwlwifi (7000-series and later) writes (queue_id << 8) | new_wptr
// to this single MMIO offset to publish a freshly-built TFD.
inline constexpr u32 kHbusTargWrptr = 0x460;

// SCD (Scheduler) per-queue read-pointer registers. The chip
// publishes its TX read pointer here once a frame is on the air;
// the driver advances `tail` to match. Layout per Linux iwlwifi
// `iwl-prph.h`: SCD_BASE=0xa02c00, queue 0's RDPTR at +0x68,
// each subsequent queue +4. The pointer is a 9-bit modular index
// (mod 512); we mask with `(ring_size - 1)` to fit our 256-entry
// rings.
inline constexpr u32 kScdQueueRdptr0 = 0xa02c68;
inline constexpr u32 kScdQueueRdptrStride = 4;

struct IwlTxRing
{
    u32 queue_id;
    u32 size;
    u32 entry_bytes;
    u32 head;        // next write index
    u32 tail;        // next completion index
    u64 dma_addr;    // physical base (0 if not allocated)
    void* virt_base; // kernel-virtual base
    u32 doorbell_count;
    u32 completion_count;
    u32 stuck_polls; // consecutive polls where head == tail and a TX was outstanding
};

struct IwlRxRing
{
    u32 size;
    u32 entry_bytes;
    u32 read_index;
    u64 dma_addr;
    void* virt_base;
    u32 frames_received;
    u32 ring_advance_count;
};

struct IwlRingState
{
    IwlTxRing tx_queues[kIwlNumTxQueues];
    IwlRxRing rx_ring;
    bool initialized;
};

::duetos::core::Result<void> IwlRingsInit(NicInfo& n, IwlRingState* state);
::duetos::core::Result<void> IwlRingsTeardown(NicInfo& n, IwlRingState* state);

/// Submit a frame descriptor on `queue_id`. v0 just records the
/// intent and returns Unsupported until the DMA arena lands.
::duetos::core::Result<void> IwlRingsSubmitTx(NicInfo& n, IwlRingState* state, u32 queue_id, const u8* frame,
                                              u32 frame_len);

/// Drain the RX ring. Calls `WirelessDeliverBeacon` etc. for each
/// retrieved frame. Returns the number of frames processed.
u32 IwlRingsServiceRx(NicInfo& n, IwlRingState* state);

/// Poll TX completions on `queue_id`: reads the chip's SCD read
/// pointer for the queue, advances `tail` to match, and reclaims
/// each completed slot. Increments `completion_count` per slot
/// reclaimed; if the queue had outstanding TX (`head != tail`)
/// but the chip reported no progress, bumps `stuck_polls` so a
/// future watchdog can spot a hung queue. Returns the number of
/// TFD slots reclaimed on this call. The IRQ handler is the
/// canonical caller; a periodic kernel poll is the fallback.
u32 IwlRingsPollTxCompletions(NicInfo& n, IwlRingState* state, u32 queue_id);

/// Test seam for `IwlRingsPollTxCompletions` — same bookkeeping,
/// but the chip-side read pointer is supplied by the caller
/// instead of being read from MMIO. Lets the self-test verify
/// the slot-reclaim walk without a live chip.
u32 IwlRingsApplyTxCompletions(IwlRingState* state, u32 queue_id, u32 chip_rdptr);

/// Per-NIC singleton activation. Called once by the (future)
/// firmware-loader slice after a successful microcode upload —
/// initializes the singleton TX/RX ring state and records the
/// owning NIC. Subsequent watch-task ticks call
/// `IwlRingsServicePending` which polls TX completions on every
/// queue. Idempotent (a second Activate on the same owner is a
/// no-op); Activate on a second NIC while one is already
/// attached returns Unsupported (v0 supports at most one
/// iwlwifi NIC).
::duetos::core::Result<void> IwlRingsActivate(NicInfo& n);

/// Tear down the singleton ring state and clear the owner.
/// Called by `NetShutdown` and when the owning NIC's
/// `driver_online` flag flips back to false. Safe if no Activate
/// preceded it.
void IwlRingsDeactivate();

/// Watch-task service hook. If a ring state is currently attached
/// to `n`, polls every TX queue for completions (the periodic-
/// poll fallback the `IwlRingsPollTxCompletions` docstring calls
/// out) and services any RX bookkeeping. Returns the total
/// number of TFD slots reclaimed across all queues (0 when no
/// rings are attached or every queue is idle). Lightweight —
/// safe to call on every watch tick without throttling.
u32 IwlRingsServicePending(NicInfo& n);

void IwlRingsSelfTest();

} // namespace duetos::drivers::net
