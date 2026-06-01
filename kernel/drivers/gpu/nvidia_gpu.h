#pragma once

#include "drivers/gpu/gpu.h"
#include "mm/dma.h" // GspRpcRing embeds mm::DmaBuffer
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — NVIDIA GeForce (Turing+) driver scaffold, v0.
 *
 * NVIDIA's modern open-kernel-modules path covers Turing (TU10x,
 * 2018) and later. PMC_BOOT_0 at BAR0+0 has been a stable
 * architecture identifier since NV4 (1998); we read it for
 * diagnostics in `gpu.cpp` and re-read it here for completeness.
 *
 * BAR layout (Turing+):
 *   BAR0  REGS    — register file (16 MiB)
 *   BAR1  FB      — VRAM framebuffer aperture (256 MiB–16 GiB)
 *   BAR3  USERD   — user-mode doorbell pages (256 MiB)
 *
 * v0 scope:
 *   - `Probe(GpuInfo&)` — read PMC_BOOT_0 / _42 / _8 for chip
 *     identification, PMC_INTR_EN_0 / PFIFO_INTR for engine
 *     liveness, PFB_PRI_RD for memory-subsystem decode. Walks the
 *     firmware loader for the GSP-related blobs (`gsp_rm.bin` /
 *     `gsp_log.bin` / `bootloader.bin`) and logs hits. Pure
 *     observation — NOT a single register is written.
 *   - `Bringup(GpuInfo&)` — allocate a 4 KiB host-system DMA
 *     buffer that would back a Channel's pushbuffer (PFIFO
 *     channel ring), log the address, return Unsupported.
 *     Unlike Intel's RCS (no firmware needed for `MI_NOOP`) and
 *     AMD's CP (a few configuration writes are safe without
 *     microcode), NVIDIA Turing+ requires the GSP RPC channel
 *     to be alive before any host-side write to a PFIFO /
 *     PGRAPH register is safe — there is no `MI_NOOP`-equivalent
 *     that bypasses GSP. So the slice stays observe-only until
 *     the GSP loader lands.
 *
 * Out of scope (v0):
 *   - GSP firmware loading + RPC channel (NVIDIA's modern drivers
 *     run the GPU System Processor firmware and talk to it over
 *     a mailbox / RPC ring to mediate every kernel-driver effect
 *     on the engine). The RPC schema is not publicly documented;
 *     the only reference is the open-source `nouveau` driver's
 *     reverse-engineered shim.
 *   - Channel allocation / context switching.
 *   - PGRAPH ctxsw register state save/restore.
 *   - Display Engine programming (modeset / cursor / OSD).
 *
 * Context: kernel. `Probe` is called from `gpu::RunVendorProbe`.
 */

namespace duetos::drivers::gpu::nvidia
{

// MMIO offsets we read in v0. All are stable across Turing+.
//
//   PMC_BOOT_0      0x000000 — chipset / arch / impl / revision
//   PMC_BOOT_42     0x00A100 — chip SKU / publisher metadata
//                              (added in Pascal; stable through
//                              Blackwell). Reads as 0 on pre-
//                              Pascal silicon.
//   PMC_BOOT_8      0x000280 — secondary revision dword
//                              (production stepping)
//   PMC_INTR_EN_0   0x000140 — top-level interrupt enable
//   PFIFO_INTR      0x002100 — host-channel scheduler interrupt
//   PFB_PRI_RD      0x100000 — framebuffer subsystem read register
//   PBUS_INTR_0     0x001100 — bus-controller interrupt status
inline constexpr u64 kNvidiaRegPmcBoot0 = 0x000000;
inline constexpr u64 kNvidiaRegPmcBoot42 = 0x00A100;
inline constexpr u64 kNvidiaRegPmcBoot8 = 0x000280;
inline constexpr u64 kNvidiaRegPmcIntrEn0 = 0x000140;
inline constexpr u64 kNvidiaRegPfifoIntr = 0x002100;
inline constexpr u64 kNvidiaRegPfbPriRd = 0x100000;
inline constexpr u64 kNvidiaRegPbusIntr0 = 0x001100;

inline constexpr u64 kNvidiaPushbufBytes = 4096;

/*
 * GSP (GPU System Processor) bring-up skeleton.
 *
 * NVIDIA Turing+ does not expose a direct host path to PFIFO /
 * PGRAPH the way Intel (MI_NOOP on RCS) or AMD (a few safe CP
 * configuration writes) do. Every kernel-driver effect on the
 * engine is mediated by firmware running on the GSP RISC-V
 * microcontroller, reached over an RPC mailbox ring. The host
 * sequence the open-gpu-kernel-modules / nouveau paths follow is:
 *
 *   1. Load + validate the per-asic `gsp_*.bin` container
 *      (NvidiaGspFwParse, already implemented in nvidia_gsp_fw.*).
 *   2. Stage the RM payload + radix-3 page tables into a WPR
 *      (Write-Protected Region) carved from the top of VRAM, then
 *      have FWSEC/SEC2 lock it (FRTS) before releasing the GSP
 *      from reset.
 *   3. Boot the GSP: write the bootloader descriptor, kick the
 *      falcon/RISC-V core, poll the boot-completion mailbox.
 *   4. Open the RPC command/message rings in system memory, hand
 *      their GPAs to the GSP, and wait for the init RPC reply.
 *   5. Submit RPCs (channel alloc, pushbuffer bind, ...) over the
 *      command ring; reap replies off the message ring.
 *
 * Steps 2-5 require real silicon, a real per-asic firmware blob,
 * and the (publicly undocumented) RPC schema. This header defines
 * the data structures and state machine for that sequence; the
 * .cpp drives them as far as it honestly can (validate firmware
 * presence, compute the WPR layout, lay out the rings in host DMA)
 * and stops at the first step that needs hardware, returning a
 * precise typed Result. None of it fakes a successful boot.
 */

/// Top-level GSP bring-up phases. The state machine advances one
/// phase at a time; a phase that needs hardware/firmware we do not
/// have stops here and the bring-up returns the matching error.
enum class GspBringupPhase : u8
{
    Idle = 0,          // nothing attempted yet
    FirmwareValidated, // gsp_*.bin found + NvidiaGspFwParse accepted it
    WprLaidOut,        // WPR base/size/sub-region offsets computed
    RingsAllocated,    // host-side command/message rings allocated + zeroed
    GspBooted,         // GSP RISC-V core released + reported boot-complete
    RpcChannelOpen,    // init RPC exchanged; ring GPAs handed to GSP
    Submitted,         // at least one RPC accepted on the command ring
};

/// WPR (Write-Protected Region) layout, computed top-down from the
/// end of VRAM. Pure arithmetic — no register touch. Mirrors the
/// `GspFwWprMeta` carve-up in open-gpu-kernel-modules: the RM
/// firmware ELF, its radix-3 page-table image, a boot-args page,
/// and a heap, all 4 KiB-aligned, packed below `vram_end`. WPR2 is
/// `[wpr_base, vram_end)`; FRTS locks it before GSP release.
struct GspWprLayout
{
    u64 vram_end;     // exclusive top-of-VRAM (BAR1 size or FB size)
    u64 wpr_base;     // inclusive base of the locked region
    u64 fw_image_off; // RM firmware ELF image (within WPR)
    u64 fw_image_size;
    u64 radix3_off; // radix-3 page-table image for the RM ELF
    u64 radix3_size;
    u64 boot_args_off; // GSP boot-arguments page
    u64 heap_off;      // RM heap base
    u64 heap_size;
};

inline constexpr u64 kGspWprAlign = 4096;             // every sub-region is page-aligned
inline constexpr u64 kGspBootArgsBytes = 4096;        // single boot-args page
inline constexpr u64 kGspDefaultHeapBytes = 0x800000; // 8 MiB RM heap (open-gpu default class)

/// RPC message ring. NVIDIA's GSP RPC is a pair of single-producer /
/// single-consumer rings (command = host->GSP, message = GSP->host)
/// in system memory, each a power-of-two count of fixed-size slots.
/// `tx`/`rx` are the producer/consumer indices the two sides bump;
/// they wrap modulo `slot_count`. This struct is the host-side
/// bookkeeping view — the on-DMA layout is the slot array backed by
/// `dma`.
struct GspRpcRing
{
    mm::DmaBuffer dma; // backing host-system DMA region (Dma32)
    u32 slot_count;    // power of two
    u32 slot_bytes;    // fixed slot size (RPC header + payload)
    u32 tx;            // producer index (host writes, GSP reads)
    u32 rx;            // consumer index (host reads, GSP writes)
};

inline constexpr u32 kGspRpcSlotCount = 16;  // power of two
inline constexpr u32 kGspRpcSlotBytes = 256; // header + small payload
inline constexpr u32 kGspRpcRingBytes = kGspRpcSlotCount * kGspRpcSlotBytes;

/// Per-message RPC header. Little-endian on the wire. The function
/// id selects the RPC; `length` covers header + payload; `sequence`
/// is echoed in the reply so the host can match a message-ring entry
/// to the command it answers. `checksum` is a simple additive sum
/// over the payload — the open-source path uses it as a cheap
/// corruption guard, not a security check.
struct GspRpcHeader
{
    u32 function; // RPC function id (e.g. kGspRpcFn*)
    u32 length;   // total bytes: kGspRpcHeaderBytes + payload
    u32 sequence; // monotonically increasing per ring
    u32 checksum; // additive sum of payload bytes
};

inline constexpr u32 kGspRpcHeaderBytes = 16; // wire size of GspRpcHeader

/// A couple of RPC function ids we name for the submit skeleton.
/// The full set is large and per-version; these are the ones the
/// state machine references so the call chain is concrete.
inline constexpr u32 kGspRpcFnNop = 0x0000'0000u;          // ping, no payload
inline constexpr u32 kGspRpcFnAllocChannel = 0x0000'1001u; // PFIFO channel alloc

/// Encode an RPC header + payload into a ring slot. Computes the
/// additive checksum over the payload and writes the little-endian
/// header. Returns `BufferTooSmall` if the slot can't hold
/// header+payload, `InvalidArgument` for a null slot. Pure; no
/// hardware. Unit-tested by the self-test.
::duetos::core::Result<void> GspRpcEncode(u8* slot, u32 slot_bytes, u32 function, const u8* payload, u32 payload_len,
                                          u32 sequence);

/// Decode an RPC header out of a ring slot and validate its
/// self-consistency (length within the slot, checksum matches the
/// payload). Returns the decoded header in `*out`. `Corrupt` on a
/// checksum/length mismatch. Pure; no hardware. Unit-tested.
::duetos::core::Result<void> GspRpcDecode(const u8* slot, u32 slot_bytes, GspRpcHeader* out);

/// Advance a ring index by one slot, wrapping at `slot_count`.
/// Split out so the wrap math is exercised by the self-test
/// independently of any ring buffer being live. `InvalidArgument`
/// when `slot_count` is not a non-zero power of two.
::duetos::core::Result<u32> GspRingAdvance(u32 index, u32 slot_count);

/// Compute the WPR layout for a firmware image of `fw_image_size`
/// bytes (RM ELF) needing `radix3_size` bytes of page tables, packed
/// top-down below `vram_end`. Returns `InvalidArgument` for a zero
/// vram_end or sizes that would underflow the region. Pure; no
/// register access — this is the math the next slice feeds to FRTS.
::duetos::core::Result<GspWprLayout> GspComputeWprLayout(u64 vram_end, u64 fw_image_size, u64 radix3_size);

/// Run the v0 probe: read PMC_BOOT_0 / _42 / _8, PFIFO + PFB +
/// PBUS diagnostics, log a one-line summary, and walk the
/// firmware-loader for the standard GSP blob names. The
/// PMC_BOOT_0 read is also done in `gpu.cpp::RunVendorProbe` —
/// we re-do it here so the driver's view and the discovery
/// layer's view are independent.
void Probe(GpuInfo& g);

/// v0 ring scaffold. Allocates a 4 KiB pushbuffer DMA region,
/// logs it, frees it, returns Unsupported. Unchanged from the
/// scaffold shape — every observable side-effect of a real
/// PFIFO channel needs the GSP RPC ring alive, which is the
/// multi-month gate this slice does NOT cross.
::duetos::core::Result<void> Bringup(GpuInfo& g);

/// True iff a successful Bringup has run. Always false today —
/// kept for symmetry with `intel::IsBroughtUp` / `amd::IsBroughtUp`
/// so callers can branch on "do we have a real GPU ring to
/// dispatch to?" with one predicate per vendor.
bool IsBroughtUp();

/// Boot self-test. Walks the GPU records discovered by
/// `gpu::GpuInit`; if an NVIDIA display controller is present,
/// emits the structural sentinel
/// `[gpu/nvidia/gsp] selftest PASS (device present, GSP RPC
/// gated)` — the slice that lands GSP push will flip this to a
/// real "channel alive" check. If no NVIDIA controller is present
/// (typical QEMU smoke), emits `[gpu/nvidia/gsp] no NVIDIA
/// device — skipped`. The sentinel is one of three CI greps for
/// to confirm the per-vendor surface stays alive.
void NvidiaGspSelfTest();

} // namespace duetos::drivers::gpu::nvidia
