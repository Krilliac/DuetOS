#include "xhci.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/result.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "usb.h"

namespace customos::drivers::usb::xhci
{

namespace
{

constexpr u32 kMaxControllers = 4;
constinit ControllerInfo g_controllers[kMaxControllers] = {};
constinit u32 g_controller_count = 0;
// File-scope "is Init live" flag so XhciShutdown can clear it and
// a subsequent XhciInit re-runs. Previously this was a function-
// static constinit bool that made Init idempotent; restartable
// drivers need the flag to be rewindable.
constinit bool g_init_done = false;

// xHCI capability-reg offsets (xHCI 1.2 §5.3).
constexpr u64 kCapHciVersion = 0x00; // u32 = caplen | (rsvd) | hciver
constexpr u64 kCapHcsParams1 = 0x04;
constexpr u64 kCapHcsParams2 = 0x08;
constexpr u64 kCapDbOff = 0x14;
constexpr u64 kCapRtsOff = 0x18;

// Operational-reg offsets (relative to opbase = mmio + caplen).
constexpr u64 kOpUsbCmd = 0x00;
constexpr u64 kOpUsbSts = 0x04;
constexpr u64 kOpDnCtrl = 0x14;
constexpr u64 kOpCrcr = 0x18;   // u64
constexpr u64 kOpDcbaap = 0x30; // u64
constexpr u64 kOpConfig = 0x38;

// USBCMD bits.
constexpr u32 kCmdRunStop = 1u << 0;
constexpr u32 kCmdHcReset = 1u << 1;

// USBSTS bits.
constexpr u32 kStsHcHalted = 1u << 0;
constexpr u32 kStsCnr = 1u << 11;

// TRB types (in TRB control field bits 15:10).
constexpr u32 kTrbTypeNoOp = 23; // command-ring NoOp
constexpr u32 kTrbTypeLink = 6;
constexpr u32 kTrbTypeEnableSlot = 9;
constexpr u32 kTrbTypeCmdCompletion = 33;
constexpr u32 kTrbTypePortStatusChange = 34;

// PORTSC bit layout we care about.
constexpr u32 kPortScCcs = 1u << 0; // current-connect status (RO)
constexpr u32 kPortScPed = 1u << 1; // port enabled/disabled (RW1C)
constexpr u32 kPortScPr = 1u << 4;  // port reset (RW1S)

// PORTSC RW1C bits (PED + the 7 change bits at 17..23). When we
// modify PORTSC we mask these out of our writeback so a status-
// change bit that the controller has set doesn't get cleared as
// a side effect of "I just wanted to write PR=1".
constexpr u32 kPortScRw1cMask = (1u << 1) | (0x7Fu << 17);

// Command Completion event: status bits 31:24 carry a completion
// code; 1 = success. Bits 23:16 carry the slot ID for commands that
// allocate one (Enable Slot in particular).
constexpr u32 kCompletionCodeSuccess = 1;

// One TRB = 16 bytes: { u32 param_lo, u32 param_hi, u32 status, u32 control }.
struct alignas(16) Trb
{
    u32 param_lo;
    u32 param_hi;
    u32 status;
    u32 control;
};

// One ERST entry = 16 bytes: { u64 ring_phys, u32 ring_size, u32 rsvd }.
struct alignas(16) ErstEntry
{
    u64 ring_phys;
    u32 ring_size;
    u32 _rsvd;
};

inline volatile u8* OpBase(const HostControllerInfo& h, u8 caplen)
{
    return static_cast<volatile u8*>(h.mmio_virt) + caplen;
}

inline u32 ReadMmio32(volatile u8* base, u64 offset)
{
    return *reinterpret_cast<volatile u32*>(base + offset);
}
inline void WriteMmio32(volatile u8* base, u64 offset, u32 value)
{
    *reinterpret_cast<volatile u32*>(base + offset) = value;
}
inline u64 ReadMmio64(volatile u8* base, u64 offset)
{
    return *reinterpret_cast<volatile u64*>(base + offset);
}
inline void WriteMmio64(volatile u8* base, u64 offset, u64 value)
{
    *reinterpret_cast<volatile u64*>(base + offset) = value;
}

// Allocate one zeroed 4 KiB frame; return both phys + kernel-virtual
// pointer. Returns false on out-of-memory.
bool AllocZeroPage(mm::PhysAddr* out_phys, void** out_virt)
{
    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
        return false;
    void* virt = mm::PhysToVirt(phys);
    if (virt == nullptr)
        return false;
    auto* p = static_cast<volatile u8*>(virt);
    for (u64 i = 0; i < mm::kPageSize; ++i)
        p[i] = 0;
    *out_phys = phys;
    *out_virt = virt;
    return true;
}

// Wait for a u32 MMIO register to satisfy `(value & mask) == match`.
// Returns true if the predicate held within `iters` polls. iters is
// a busy-loop count; tuned conservatively (1M ≈ tens of ms on QEMU)
// because we're called from boot context with the timer not yet
// running self-test logic that would care about the exact wall time.
bool PollUntil(volatile u8* base, u64 reg_off, u32 mask, u32 match, u64 iters)
{
    for (u64 i = 0; i < iters; ++i)
    {
        const u32 v = ReadMmio32(base, reg_off);
        if ((v & mask) == match)
            return true;
        // tight-spin: a `pause` reduces power + signals the CPU
        // we're in a wait loop.
        asm volatile("pause" : : : "memory");
    }
    return false;
}

bool InitOne(const HostControllerInfo& h, ControllerInfo& out)
{
    out.bus = h.bus;
    out.device = h.device;
    out.function = h.function;
    out.init_ok = false;
    out.noop_ok = false;

    if (h.kind != HciKind::Xhci || h.mmio_virt == nullptr)
        return false;

    auto* mmio = static_cast<volatile u8*>(h.mmio_virt);
    const u32 cap_word = ReadMmio32(mmio, kCapHciVersion);
    const u8 caplen = u8(cap_word & 0xFF);
    if (caplen < 0x20)
    {
        arch::SerialWrite("[xhci] caplen below spec minimum, skipping\n");
        return false;
    }
    volatile u8* op = OpBase(h, caplen);

    // Spec §4.2: stop the controller before reset (RUN/STOP=0 then
    // wait for HCH=1), then HCRST=1 and wait for it to clear and
    // for CNR=0.
    u32 cmd = ReadMmio32(op, kOpUsbCmd);
    if (cmd & kCmdRunStop)
    {
        WriteMmio32(op, kOpUsbCmd, cmd & ~kCmdRunStop);
        if (!PollUntil(op, kOpUsbSts, kStsHcHalted, kStsHcHalted, 1'000'000))
        {
            arch::SerialWrite("[xhci] timed out waiting for HCH=1 before reset\n");
            return false;
        }
    }
    WriteMmio32(op, kOpUsbCmd, ReadMmio32(op, kOpUsbCmd) | kCmdHcReset);
    // After reset both HCRST and CNR must be 0.
    if (!PollUntil(op, kOpUsbCmd, kCmdHcReset, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] HCRST never cleared\n");
        return false;
    }
    if (!PollUntil(op, kOpUsbSts, kStsCnr, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] CNR never cleared after reset\n");
        return false;
    }

    // Cache geometry the spec requires before allocating data structures.
    const u32 hcs1 = ReadMmio32(mmio, kCapHcsParams1);
    const u32 hcs2 = ReadMmio32(mmio, kCapHcsParams2);
    out.max_slots = u8(hcs1 & 0xFF);
    out.max_intrs = u16((hcs1 >> 8) & 0x7FF);
    out.max_ports = u8((hcs1 >> 24) & 0xFF);
    const u32 sp_lo = (hcs2 >> 27) & 0x1F;
    const u32 sp_hi = (hcs2 >> 21) & 0x1F;
    out.max_scratchpad = (sp_hi << 5) | sp_lo;

    if (out.max_scratchpad != 0)
    {
        // QEMU q35 default doesn't ask for scratchpad; if a real
        // controller does, bail v0 (proper handling needs N more
        // pages + a pointer-array page).
        arch::SerialWrite("[xhci] controller requests scratchpad buffers — v0 doesn't allocate, skipping\n");
        return false;
    }
    if (out.max_slots == 0)
    {
        arch::SerialWrite("[xhci] controller reports max_slots=0, skipping\n");
        return false;
    }

    // Allocate DCBAA, command ring, event ring, ERST.
    mm::PhysAddr dcbaa_phys = 0;
    void* dcbaa_virt = nullptr;
    if (!AllocZeroPage(&dcbaa_phys, &dcbaa_virt))
        return false;
    mm::PhysAddr cmd_phys = 0;
    void* cmd_virt = nullptr;
    if (!AllocZeroPage(&cmd_phys, &cmd_virt))
        return false;
    mm::PhysAddr evt_phys = 0;
    void* evt_virt = nullptr;
    if (!AllocZeroPage(&evt_phys, &evt_virt))
        return false;
    mm::PhysAddr erst_phys = 0;
    void* erst_virt = nullptr;
    if (!AllocZeroPage(&erst_phys, &erst_virt))
        return false;

    out.dcbaa_phys = dcbaa_phys;
    out.cmd_ring_phys = cmd_phys;
    out.event_ring_phys = evt_phys;
    out.erst_phys = erst_phys;

    // Command ring: install a Link TRB at the last slot pointing
    // back to ring base, with Toggle Cycle = 1 so the controller
    // flips its own cycle bit when it wraps.
    auto* cmd_ring = static_cast<Trb*>(cmd_virt);
    constexpr u32 kRingSlots = mm::kPageSize / sizeof(Trb);
    Trb& link = cmd_ring[kRingSlots - 1];
    link.param_lo = u32(cmd_phys);
    link.param_hi = u32(cmd_phys >> 32);
    link.status = 0;
    // control = (TRB type << 10) | TC=1 (bit 1) | C=1 (bit 0).
    // We set the cycle bit so the link entry matches our initial
    // "producer cycle" state of 1.
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    // ERST entry 0 points at the event ring with size = ring slots.
    auto* erst = static_cast<ErstEntry*>(erst_virt);
    erst[0].ring_phys = evt_phys;
    erst[0].ring_size = kRingSlots;
    erst[0]._rsvd = 0;

    // Wire op-regs.
    // CONFIG.MaxSlotsEn = max_slots (cap-reported limit).
    WriteMmio32(op, kOpConfig, out.max_slots);
    // DCBAAP — physical base; alignment is 64 bytes, our page is
    // 4 KiB so safely aligned.
    WriteMmio64(op, kOpDcbaap, dcbaa_phys);
    // CRCR — command-ring base | bit 0 (Ring Cycle State = 1).
    // Other bits (Command Stop, Command Abort) start cleared.
    WriteMmio64(op, kOpCrcr, cmd_phys | 1u);
    // DNCTRL: enable bus-master notification for slot 0 only (default).
    WriteMmio32(op, kOpDnCtrl, 0x2);

    // Interrupter 0 lives in the runtime register set: rt_base =
    // mmio + RTSOFF; per-interrupter stride 32 B starting at +0x20.
    const u32 rtsoff = ReadMmio32(mmio, kCapRtsOff) & ~0x1Fu;
    volatile u8* intr0 = mmio + rtsoff + 0x20;
    constexpr u64 kIntrErstSz = 0x08;   // u32
    constexpr u64 kIntrErstBaLo = 0x10; // u32 (low half of u64)
    constexpr u64 kIntrErstBaHi = 0x14;
    constexpr u64 kIntrErdpLo = 0x18; // u64
    WriteMmio32(intr0, kIntrErstSz, 1);
    // ERDP must be written BEFORE ERSTBA per spec §4.9.4.
    WriteMmio64(intr0, kIntrErdpLo, evt_phys);
    WriteMmio64(intr0, kIntrErstBaLo, erst_phys);

    // Start the controller. RS=1, then wait for HCH=0.
    WriteMmio32(op, kOpUsbCmd, ReadMmio32(op, kOpUsbCmd) | kCmdRunStop);
    if (!PollUntil(op, kOpUsbSts, kStsHcHalted, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] HCH never cleared after RS=1\n");
        return false;
    }
    out.init_ok = true;

    // Generic command submit/complete state. We never wrap the
    // command ring during boot (≤ a few dozen commands across
    // every controller), so the panic-on-wrap below is fine for
    // v0; the proper Link-TRB cycle-toggle happens when the first
    // real workload actually fills 255 slots.
    auto* evt_ring = static_cast<Trb*>(evt_virt);
    constexpr u32 kRingSlotsLocal = mm::kPageSize / sizeof(Trb);
    u32 cmd_producer_idx = 0;
    u32 cmd_producer_cycle = 1;
    u32 evt_consumer_idx = 0;
    u32 evt_consumer_cycle = 1;

    const u32 dboff = ReadMmio32(mmio, kCapDbOff) & ~0x3u;
    volatile u32* db0 = reinterpret_cast<volatile u32*>(mmio + dboff);

    auto submit_cmd = [&](u32 type, u32 param_lo, u32 param_hi, u32 status_field, u32 extra_control) -> u64
    {
        if (cmd_producer_idx >= kRingSlotsLocal - 1)
        {
            arch::SerialWrite("[xhci] command ring exhausted (link-TRB wrap not implemented for v0)\n");
            return 0;
        }
        Trb& slot = cmd_ring[cmd_producer_idx];
        slot.param_lo = param_lo;
        slot.param_hi = param_hi;
        slot.status = status_field;
        slot.control = (type << 10) | (extra_control & ~1u) | (cmd_producer_cycle & 1u);
        const u64 phys = cmd_phys + u64(cmd_producer_idx) * sizeof(Trb);
        ++cmd_producer_idx;
        // Doorbell write: target=0 (command ring) is bits 7..0; bits
        // 23..16 = stream-id (unused for cmd ring).
        *db0 = 0;
        return phys;
    };

    // Wait for a Command Completion event whose CommandTRB pointer
    // matches `expect_phys`. On success returns true and writes the
    // 32-bit completion-status word + the slot ID extracted from
    // bits 23:16 of that word into `*out_slot_id`.
    auto wait_completion = [&](u64 expect_phys, u32* out_status, u8* out_slot_id) -> bool
    {
        for (u64 i = 0; i < 4'000'000; ++i)
        {
            const Trb& e = evt_ring[evt_consumer_idx];
            const bool valid = (e.control & 1u) == (evt_consumer_cycle & 1u);
            if (valid)
            {
                const u32 type = (e.control >> 10) & 0x3F;
                if (type == kTrbTypeCmdCompletion)
                {
                    const u64 ptr = (u64(e.param_hi) << 32) | u64(e.param_lo);
                    if (ptr == expect_phys)
                    {
                        if (out_status != nullptr)
                            *out_status = e.status;
                        if (out_slot_id != nullptr)
                            *out_slot_id = u8((e.control >> 24) & 0xFF);
                        ++evt_consumer_idx;
                        if (evt_consumer_idx >= kRingSlotsLocal)
                        {
                            evt_consumer_idx = 0;
                            evt_consumer_cycle ^= 1;
                        }
                        // Advance ERDP: bit 3 = "Event Handler Busy"
                        // (write 1 to clear). Pointer goes in
                        // bits 63:4.
                        const u64 erdp = evt_phys + u64(evt_consumer_idx) * sizeof(Trb);
                        WriteMmio64(intr0, /*kIntrErdpLo=*/0x18, erdp | (1ull << 3));
                        return true;
                    }
                }
                // Some other (non-matching) event came in. Drop it
                // and advance — we don't care about port-status
                // change events as side effects of the reset.
                ++evt_consumer_idx;
                if (evt_consumer_idx >= kRingSlotsLocal)
                {
                    evt_consumer_idx = 0;
                    evt_consumer_cycle ^= 1;
                }
                const u64 erdp = evt_phys + u64(evt_consumer_idx) * sizeof(Trb);
                WriteMmio64(intr0, /*kIntrErdpLo=*/0x18, erdp | (1ull << 3));
                continue;
            }
            asm volatile("pause" : : : "memory");
        }
        return false;
    };

    // NoOp roundtrip — proves the submit/complete plumbing works
    // before we issue commands that allocate state on the controller.
    {
        const u64 noop_phys = submit_cmd(kTrbTypeNoOp, 0, 0, 0, 0);
        u32 status = 0;
        u8 slot = 0;
        out.noop_ok = (noop_phys != 0) && wait_completion(noop_phys, &status, &slot);
    }

    arch::SerialWrite("[xhci] init pci=");
    arch::SerialWriteHex(h.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(h.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(h.function);
    arch::SerialWrite(" max_slots=");
    arch::SerialWriteHex(out.max_slots);
    arch::SerialWrite(" max_ports=");
    arch::SerialWriteHex(out.max_ports);
    arch::SerialWrite(" max_intrs=");
    arch::SerialWriteHex(out.max_intrs);
    arch::SerialWrite(" dcbaa=");
    arch::SerialWriteHex(out.dcbaa_phys);
    arch::SerialWrite(" cmd_ring=");
    arch::SerialWriteHex(out.cmd_ring_phys);
    arch::SerialWrite(" event_ring=");
    arch::SerialWriteHex(out.event_ring_phys);
    arch::SerialWrite("\n");
    arch::SerialWrite(out.noop_ok ? "[xhci] NoOp roundtrip PASS\n"
                                  : "[xhci] NoOp roundtrip FAIL — no Command Completion event\n");

    if (!out.noop_ok)
        return true;

    // Walk PORTSC for every port. Per-port PORTSC starts at
    // opbase + 0x400 + (port_idx * 0x10). For each port that
    // shows CCS=1: kick PR=1 if not already enabled, wait for
    // PED=1, then issue Enable Slot Command.
    out.ports_connected = 0;
    out.slots_enabled = 0;
    const u8 ports_to_scan = (out.max_ports < kMaxXhciPortsPerController) ? out.max_ports : kMaxXhciPortsPerController;
    for (u8 i = 0; i < ports_to_scan; ++i)
    {
        const u64 portsc_off = 0x400 + u64(i) * 0x10;
        u32 portsc = ReadMmio32(op, portsc_off);
        PortRecord& rec = out.ports[i];
        rec.port_num = u8(i + 1);
        rec.connected = (portsc & kPortScCcs) != 0;
        rec.portsc_at_scan = portsc;
        rec.speed = (portsc >> 10) & 0xF;
        if (!rec.connected)
            continue;
        ++out.ports_connected;

        // Reset only if PED is not already set. USB 3 ports usually
        // self-train and arrive with PED=1; USB 2 ports require PR=1.
        if ((portsc & kPortScPed) == 0)
        {
            const u32 wr = (portsc & ~kPortScRw1cMask) | kPortScPr;
            WriteMmio32(op, portsc_off, wr);
            // Wait for PR to clear (reset done) and PED to set.
            for (u64 j = 0; j < 1'000'000; ++j)
            {
                const u32 cur = ReadMmio32(op, portsc_off);
                if ((cur & kPortScPr) == 0 && (cur & kPortScPed) != 0)
                {
                    portsc = cur;
                    break;
                }
                asm volatile("pause" : : : "memory");
            }
        }
        rec.reset_ok = (ReadMmio32(op, portsc_off) & kPortScPed) != 0;
        if (!rec.reset_ok)
        {
            arch::SerialWrite("[xhci]   port ");
            arch::SerialWriteHex(rec.port_num);
            arch::SerialWrite(" connected but PED never set after reset\n");
            continue;
        }

        // Send Enable Slot Command. param_lo/hi/status all zero.
        const u64 cmd_p = submit_cmd(kTrbTypeEnableSlot, 0, 0, 0, 0);
        u32 cs = 0;
        u8 slot_id = 0;
        if (cmd_p != 0 && wait_completion(cmd_p, &cs, &slot_id))
        {
            const u32 code = (cs >> 24) & 0xFF;
            if (code == kCompletionCodeSuccess && slot_id != 0)
            {
                rec.slot_ok = true;
                rec.slot_id = slot_id;
                ++out.slots_enabled;
            }
            else
            {
                arch::SerialWrite("[xhci]   port ");
                arch::SerialWriteHex(rec.port_num);
                arch::SerialWrite(" Enable Slot completed with code=");
                arch::SerialWriteHex(code);
                arch::SerialWrite("\n");
            }
        }
        else
        {
            arch::SerialWrite("[xhci]   port ");
            arch::SerialWriteHex(rec.port_num);
            arch::SerialWrite(" Enable Slot timed out\n");
        }

        arch::SerialWrite("[xhci]   port ");
        arch::SerialWriteHex(rec.port_num);
        arch::SerialWrite(" connected speed=");
        arch::SerialWriteHex(rec.speed);
        arch::SerialWrite(rec.slot_ok ? " slot_id=" : " slot=fail");
        if (rec.slot_ok)
            arch::SerialWriteHex(rec.slot_id);
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[xhci] port scan: connected=");
    arch::SerialWriteHex(out.ports_connected);
    arch::SerialWrite(" slots_enabled=");
    arch::SerialWriteHex(out.slots_enabled);
    arch::SerialWrite("\n");
    return true;
}

} // namespace

void XhciInit()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciInit");
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = HostControllerCount();
    for (u64 i = 0; i < n && g_controller_count < kMaxControllers; ++i)
    {
        const HostControllerInfo& h = HostController(i);
        if (h.kind != HciKind::Xhci)
            continue;
        ControllerInfo& slot = g_controllers[g_controller_count];
        if (InitOne(h, slot))
            ++g_controller_count;
    }
    if (g_controller_count == 0)
    {
        arch::SerialWrite("[xhci] no controllers brought up\n");
    }
    else
    {
        arch::SerialWrite("[xhci] controllers brought up: ");
        arch::SerialWriteHex(g_controller_count);
        arch::SerialWrite("\n");
    }
}

::customos::core::Result<void> XhciShutdown()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciShutdown");
    using ::customos::core::Err;
    using ::customos::core::ErrorCode;
    // For each live controller: clear RUN/STOP, wait for HCH=1,
    // write CRCR / DCBAAP / ERSTBA to 0 so the hardware forgets
    // our ring addresses. The kernel frames behind the rings stay
    // leaked in v0 (intentional — AllocateFrame can't safely take
    // back a frame the controller might still DMA to until we've
    // proven HCH latched; freeing them conservatively is a
    // follow-up). g_controller_count resets so the next Init
    // starts with fresh slot indices.
    bool any_stuck = false;
    for (u32 i = 0; i < g_controller_count; ++i)
    {
        ControllerInfo& c = g_controllers[i];
        if (!c.init_ok)
            continue;
        // Re-derive MMIO base from the USB-driver record so we
        // don't have to cache a volatile pointer on ControllerInfo.
        const u64 pci_n = HostControllerCount();
        volatile u8* mmio = nullptr;
        for (u64 k = 0; k < pci_n; ++k)
        {
            const HostControllerInfo& h = HostController(k);
            if (h.bus == c.bus && h.device == c.device && h.function == c.function && h.mmio_virt != nullptr)
            {
                mmio = static_cast<volatile u8*>(h.mmio_virt);
                break;
            }
        }
        if (mmio == nullptr)
        {
            any_stuck = true;
            continue;
        }
        const u32 cap_word = ReadMmio32(mmio, kCapHciVersion);
        const u8 caplen = u8(cap_word & 0xFF);
        if (caplen < 0x20)
        {
            any_stuck = true;
            continue;
        }
        volatile u8* op = mmio + caplen;
        // Clear RUN/STOP then wait for HCH. Spec says this
        // completes within 16 ms; cap at 1M iterations (~tens of ms
        // on QEMU).
        u32 cmd = ReadMmio32(op, kOpUsbCmd);
        WriteMmio32(op, kOpUsbCmd, cmd & ~kCmdRunStop);
        if (!PollUntil(op, kOpUsbSts, kStsHcHalted, kStsHcHalted, 1'000'000))
        {
            arch::SerialWrite("[xhci] shutdown: HCH never set on pci=");
            arch::SerialWriteHex(c.bus);
            arch::SerialWrite(":");
            arch::SerialWriteHex(c.device);
            arch::SerialWrite(".");
            arch::SerialWriteHex(c.function);
            arch::SerialWrite("\n");
            any_stuck = true;
            continue;
        }
        // Zero out the ring-pointer registers. New init will
        // repopulate them with fresh frames.
        WriteMmio64(op, kOpDcbaap, 0);
        WriteMmio64(op, kOpCrcr, 0);
        // Interrupter 0's ERSTBA / ERDP / ERSTSZ.
        const u32 rtsoff = ReadMmio32(mmio, kCapRtsOff) & ~0x1Fu;
        volatile u8* intr0 = mmio + rtsoff + 0x20;
        WriteMmio32(intr0, /*kIntrErstSz=*/0x08, 0);
        WriteMmio64(intr0, /*kIntrErdp=*/0x18, 0);
        WriteMmio64(intr0, /*kIntrErstBa=*/0x10, 0);
        c.init_ok = false;
        c.noop_ok = false;
    }
    g_controller_count = 0;
    g_init_done = false;
    arch::SerialWrite(any_stuck ? "[xhci] shutdown partial (some controllers wouldn't halt)\n"
                                : "[xhci] shutdown ok — all controllers quiesced\n");
    if (any_stuck)
        return Err{ErrorCode::BadState};
    return {};
}

::customos::core::Result<void> XhciRestart()
{
    if (auto r = XhciShutdown(); !r)
        return r;
    XhciInit();
    return {};
}

u32 XhciCount()
{
    return g_controller_count;
}

const ControllerInfo* XhciControllerAt(u32 i)
{
    if (i >= g_controller_count)
        return nullptr;
    return &g_controllers[i];
}

} // namespace customos::drivers::usb::xhci
