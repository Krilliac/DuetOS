// Synthesised ACPI table set. DuetOS PANICS if no RSDP reaches it
// (kernel/acpi/acpi.cpp: "no ACPI RSDP tag in Multiboot2 info"), so
// the VMM must hand it a minimally-valid RSDP -> XSDT -> { FADT,
// MADT } -> DSDT/FACS chain. MADT advertises exactly one LAPIC +
// one IOAPIC, which also gives us clean single-vCPU boot (no APs).
#pragma once

#include <cstdint>
#include <vector>

namespace duetos::vmm
{

struct AcpiImage
{
    // Concatenated XSDT/FADT/MADT/DSDT/FACS, to be written verbatim
    // into guest RAM at `baseGpa`.
    std::vector<uint8_t> blob;
    uint64_t baseGpa = 0;

    // 36-byte ACPI 2.0 RSDP, to be embedded in the Multiboot2
    // "ACPI new" tag (type 15). Its XsdtAddress points into `blob`.
    std::vector<uint8_t> rsdp;
};

// Builds the table set so its child tables live at [baseGpa, ...).
// `lapicCount` is fixed at 1 for v0 but is explicit so the SMP slice
// widens the MADT without an API change.
AcpiImage BuildAcpi(uint64_t baseGpa, uint32_t lapicCount = 1);

} // namespace duetos::vmm
