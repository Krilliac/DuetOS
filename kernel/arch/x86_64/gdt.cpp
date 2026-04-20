#include "gdt.h"

namespace customos::arch
{

namespace
{

// Long-mode GDT descriptors. Each is 64 bits; the layout is fossil from the
// 16-bit era but we only care about a handful of fields:
//   0x9A = P | DPL=0 | S | exec/read code
//   0x92 = P | DPL=0 | S | read/write data
//   0xA  (high nibble of flags) = G=1 | L=1 | DB=0   (code)
//   0xA  (high nibble of flags) = G=1 | L=0 | DB=0   (data — L ignored)
//
// Base=0 and limit=0xFFFFF are the standard flat-long-mode values. The CPU
// ignores base/limit checks in long mode except for FS/GS, but zeroing them
// keeps things tidy.
constexpr u64 kGdtNull       = 0x0000000000000000ULL;
constexpr u64 kGdtKernelCode = 0x00AF9A000000FFFFULL;
constexpr u64 kGdtKernelData = 0x00AF92000000FFFFULL;

alignas(16) constinit u64 g_gdt[3] = {
    kGdtNull,
    kGdtKernelCode,
    kGdtKernelData,
};

struct [[gnu::packed]] GdtPointer
{
    u16 limit;
    u64 base;
};

// Not constinit — the base field requires a reinterpret_cast on a non-
// constexpr address, which the standard forbids from constant initializers.
// Filled in at runtime inside GdtInit().
GdtPointer g_gdt_pointer;

} // namespace

void GdtInit()
{
    g_gdt_pointer.limit = sizeof(g_gdt) - 1;
    g_gdt_pointer.base  = reinterpret_cast<u64>(&g_gdt[0]);

    // Load the new GDT. The CPU's cached segment descriptors still reference
    // the boot.S table until we reload each segment register, so we follow
    // lgdt with a far-return to reload CS and explicit writes for the data
    // selectors.
    asm volatile(
        "lgdt %[gdtp]                 \n\t"
        // Far-return trick to reload CS: push new CS, push the "return"
        // address (label 1 below), then lretq. On return execution
        // continues at label 1 with CS = kKernelCodeSelector.
        "pushq %[kcode]               \n\t"
        "leaq  1f(%%rip), %%rax       \n\t"
        "pushq %%rax                  \n\t"
        "lretq                        \n\t"
        "1:                           \n\t"
        // Reload data segments to pick up the new GDT's cached descriptors.
        "movw %[kdata], %%ax          \n\t"
        "movw %%ax,     %%ds          \n\t"
        "movw %%ax,     %%es          \n\t"
        "movw %%ax,     %%fs          \n\t"
        "movw %%ax,     %%gs          \n\t"
        "movw %%ax,     %%ss          \n\t"
        :
        : [gdtp]  "m"(g_gdt_pointer),
          [kcode] "i"(kKernelCodeSelector),
          [kdata] "i"(kKernelDataSelector)
        : "rax", "memory"
    );
}

} // namespace customos::arch
