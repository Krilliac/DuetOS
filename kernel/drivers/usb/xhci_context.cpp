/*
 * DuetOS — xHCI driver: Input Context builders.
 *
 * Sibling TU. Houses the two pure-layout functions that fill in
 * the spec-shaped xHCI 1.2 §6.2.5.1 Input Context:
 *
 *   BuildAddressDeviceInputContext     — slot + EP0 for Address Device
 *   BuildConfigureEndpointInputContext — slot + one new EP for Configure Endpoint
 *
 * No controller state, no MMIO, no rings — caller passes the
 * destination region (volatile-pointable, 32- or 64-byte ctx_bytes
 * per HCCPARAMS1.CSZ) and the parameters; this TU lays out the
 * bytes the controller expects.
 */

#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

// Build Input Context for Address Device. ctx_bytes is 32 or 64 per
// HCCPARAMS1.CSZ. Layout (indexes are 0-based in units of ctx_bytes):
//   [0] Input Control Context — A0|A1 set (add slot + EP0)
//   [1] Slot Context          — root-hub port, speed, ctx entries=1
//   [2] EP0 Endpoint Context  — EP type=Control, MPS, TR deq ptr
// EP2..31 stay zero (not being added).
void BuildAddressDeviceInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u32 mps0,
                                    u64 ep0_ring_phys)
{
    auto* base = static_cast<volatile u8*>(input_ctx_virt);
    // Zero the whole region we'll touch (control + slot + EP0 contexts).
    for (u32 i = 0; i < 3 * ctx_bytes; ++i)
        base[i] = 0;

    volatile u32* icc = reinterpret_cast<volatile u32*>(base + 0 * ctx_bytes);
    // D0 (drop) = 0, D1 = 0. A0 = add slot context, A1 = add EP0
    // context. xHCI 1.2 §6.2.5.1.
    icc[1] = (1u << 0) | (1u << 1);

    volatile u32* slot = reinterpret_cast<volatile u32*>(base + 1 * ctx_bytes);
    // DW0: route string (bits 0..19) = 0, speed (bits 20..23),
    // context entries (bits 27..31) = 1 (just EP0).
    slot[0] = (u32(speed) << 20) | (1u << 27);
    // DW1: root hub port number (bits 16..23).
    slot[1] = u32(port_num) << 16;

    volatile u32* ep0 = reinterpret_cast<volatile u32*>(base + 2 * ctx_bytes);
    // DW0: EP State (bits 0..2) = 0 (Disabled initial).
    ep0[0] = 0;
    // DW1: EP Type = 4 (Control) in bits 3..5. CErr (error count) =
    // 3 in bits 1..2. Max Packet Size in bits 16..31.
    ep0[1] = (3u << 1) | (4u << 3) | (mps0 << 16);
    // DW2/DW3: TR Dequeue Pointer (64-bit, bit 0 = Dequeue Cycle
    // State = 1 on first use).
    const u64 tr_dcs = ep0_ring_phys | 1ull;
    ep0[2] = u32(tr_dcs);
    ep0[3] = u32(tr_dcs >> 32);
    // DW4: Average TRB Length (bits 0..15) — we guess 8 for control
    // since every packet is an 8-byte setup packet or small status.
    ep0[4] = 8;
}

// Build a Configure Endpoint Input Context for adding ONE new
// endpoint on top of the EP0 context already established at
// Address Device time. Only the slot context (A0) and the new
// endpoint (A_dci) are flagged — EP0 stays untouched because
// it's already in Running state from Address Device. Marking A1
// here would try to reconfigure a live EP0 and the controller
// rejects it as TRB Error.
void BuildConfigureEndpointInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u8 new_dci,
                                        u32 new_ep_type, u32 new_mps, u32 new_interval, u64 new_ring_phys)
{
    auto* base = static_cast<volatile u8*>(input_ctx_virt);
    // Zero the range we'll touch (Input Control + Slot + up to new_dci endpoint ctx).
    const u32 end = (new_dci + 1) * ctx_bytes;
    for (u32 i = 0; i < end; ++i)
        base[i] = 0;

    volatile u32* icc = reinterpret_cast<volatile u32*>(base + 0 * ctx_bytes);
    // Add flags — A0 (slot context has new context-entries
    // high-water) + A(new_dci) (the endpoint we're adding).
    // A1 deliberately NOT set: re-flagging a running EP0 fails.
    icc[1] = (1u << 0) | (1u << new_dci);

    // Slot Context — context-entries high-water raised to new_dci.
    volatile u32* slot = reinterpret_cast<volatile u32*>(base + 1 * ctx_bytes);
    slot[0] = (u32(speed) << 20) | (u32(new_dci) << 27);
    slot[1] = u32(port_num) << 16;

    // New endpoint context at index new_dci.
    volatile u32* ep = reinterpret_cast<volatile u32*>(base + new_dci * ctx_bytes);
    // DW0: Interval in bits 16..23 (xHCI encoding, 2^N × 125 µs).
    ep[0] = (new_interval & 0xFF) << 16;
    // DW1: CErr=3, EP Type, Max Packet Size.
    ep[1] = (3u << 1) | (new_ep_type << 3) | (new_mps << 16);
    const u64 ep_dcs = new_ring_phys | 1ull;
    ep[2] = u32(ep_dcs);
    ep[3] = u32(ep_dcs >> 32);
    // DW4: Average TRB Length (bits 0..15) + Max ESIT Payload Lo
    // (bits 16..31). Periodic endpoints MUST set MaxESITPayload or
    // the controller rejects Configure Endpoint as TRB Error. For
    // HID Boot Keyboard: MPS × Max Burst Size = 8 × 1 = 8, which
    // is also a fine value for Average TRB Length.
    ep[4] = (new_mps & 0xFFFFu) | (new_mps << 16);
}

} // namespace duetos::drivers::usb::xhci::internal
