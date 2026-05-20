// GuestKernelView — typed live view of curated guest kernel globals.
//
// Each field is a host pointer into the WHP-mapped guest physical RAM.
// Because WHP memory is host-backed, writing through one of these
// pointers directly modifies the bytes the guest reads, with no
// additional IPI or hypercall needed.
//
// Population: RefreshGuestView() is called on every guest exit.
// Mapping is idempotent — once a field is non-null it is never
// re-resolved. Fields that cannot be resolved (symbol absent, GPA
// translation fails, or host ptr is null) remain nullptr and are
// safe to read from the VS Watch window (they just show as a null
// pointer dereference).
//
// To expose a new kernel global:
//  1. Add a typed pointer field here with a comment naming the kernel
//     symbol and its declaring TU.
//  2. Add a MapSym call in RefreshGuestView (guest_view.cpp).
//  3. For non-primitive types, add a POD mirror struct in
//     guest_types_mirror.h (not yet created — only needed when the
//     first non-primitive field lands).
#pragma once
#include <cstdint>

namespace duetos::vmm
{
class Vmm;

struct GuestKernelView
{
    // duetos::arch::(anonymous namespace)::g_ticks
    // Declared in kernel/arch/x86_64/timer.cpp (or equivalent).
    // Incremented by the LAPIC timer IRQ at 100 Hz.
    uint64_t* g_ticks = nullptr;

    // Add new exposures below — see RefreshGuestView in
    // guest_view.cpp for how. Non-primitive types need a Mirror
    // struct in guest_types_mirror.h.
};

// Attempt resolution of any still-null fields. Called on every guest
// exit; no-ops for fields already mapped (idempotent). Safe to call
// before the guest has set up paging — fields remain nullptr until
// the GVA→GPA walk succeeds.
void RefreshGuestView(GuestKernelView& view, Vmm& vmm);

} // namespace duetos::vmm
