#include "xhci.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
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
constexpr u32 kTrbTypeCmdCompletion = 33;

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

    // Build a NoOp TRB at command ring slot 0 with Cycle=1.
    Trb& noop = cmd_ring[0];
    noop.param_lo = 0;
    noop.param_hi = 0;
    noop.status = 0;
    noop.control = (kTrbTypeNoOp << 10) | 1u;

    // Doorbell 0 = command ring; written value = stream/target.
    // For the command ring you just write 0 to ring it.
    const u32 dboff = ReadMmio32(mmio, kCapDbOff) & ~0x3u;
    volatile u32* db0 = reinterpret_cast<volatile u32*>(mmio + dboff);
    *db0 = 0;

    // Poll the event ring for a Command Completion event whose
    // CommandTRB pointer points to our noop's physical address.
    auto* evt_ring = static_cast<Trb*>(evt_virt);
    const u64 noop_phys = cmd_phys; // slot 0
    bool got = false;
    for (u64 i = 0; i < 2'000'000; ++i)
    {
        const Trb& e = evt_ring[0];
        const bool valid_cycle = (e.control & 1u) == 1u;
        const u32 type = (e.control >> 10) & 0x3F;
        if (valid_cycle && type == kTrbTypeCmdCompletion)
        {
            const u64 cmd_ptr = (u64(e.param_hi) << 32) | u64(e.param_lo);
            if (cmd_ptr == noop_phys)
            {
                got = true;
                break;
            }
        }
        asm volatile("pause" : : : "memory");
    }
    out.noop_ok = got;

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

    return true;
}

} // namespace

void XhciInit()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciInit");
    static constinit bool s_done = false;
    if (s_done)
        return;
    s_done = true;

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
