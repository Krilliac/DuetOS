#include "acpi.h"

#include <cstring>

namespace duetos::vmm
{

namespace
{

uint8_t Checksum(const uint8_t* p, size_t n)
{
    uint8_t s = 0;
    for (size_t i = 0; i < n; ++i)
    {
        s = static_cast<uint8_t>(s + p[i]);
    }
    return static_cast<uint8_t>(0u - s);
}

void Put32(std::vector<uint8_t>& v, size_t off, uint32_t x)
{
    std::memcpy(v.data() + off, &x, 4);
}
void Put64(std::vector<uint8_t>& v, size_t off, uint64_t x)
{
    std::memcpy(v.data() + off, &x, 8);
}

// Writes the 36-byte System Description Table header in-place and
// fixes Length + Checksum once the body is fully populated.
void FinishTable(std::vector<uint8_t>& t, const char sig[4])
{
    std::memcpy(t.data() + 0, sig, 4);
    Put32(t, 4, static_cast<uint32_t>(t.size())); // Length
    t[8] = 1;                                     // Revision
    std::memcpy(t.data() + 10, "DUETOS", 6);      // OEMID
    std::memcpy(t.data() + 16, "DUETVMM ", 8);    // OEM Table ID
    Put32(t, 24, 1);                              // OEM Revision
    std::memcpy(t.data() + 28, "DTVM", 4);        // Creator ID
    Put32(t, 32, 1);                              // Creator Revision
    t[9] = 0;
    t[9] = Checksum(t.data(), t.size());          // Checksum
}

std::vector<uint8_t> BuildFacs()
{
    std::vector<uint8_t> f(64, 0);
    std::memcpy(f.data(), "FACS", 4);
    Put32(f, 4, 64); // Length
    return f;        // FACS carries no checksum field
}

std::vector<uint8_t> BuildDsdt()
{
    // Header-only DSDT: a valid, empty AML namespace. The kernel's
    // AML parser logs a non-fatal "diag root absent" WARN; it does
    // not panic. A real DSDT lands when a slice needs _S5/GPE.
    std::vector<uint8_t> d(36, 0);
    FinishTable(d, "DSDT");
    return d;
}

std::vector<uint8_t> BuildMadt(uint32_t lapicCount)
{
    std::vector<uint8_t> m(44, 0);          // 36 hdr + 8 MADT fixed
    Put32(m, 36, 0xFEE00000);               // Local APIC address
    Put32(m, 40, 1);                        // Flags: PCAT_COMPAT

    for (uint32_t i = 0; i < lapicCount; ++i)
    {
        const uint8_t e[8] = {0, 8, static_cast<uint8_t>(i),
                              static_cast<uint8_t>(i), 1, 0, 0, 0};
        m.insert(m.end(), e, e + 8);        // Processor Local APIC
    }

    std::vector<uint8_t> io(12, 0);
    io[0] = 1;                              // type: I/O APIC
    io[1] = 12;                             // length
    io[2] = static_cast<uint8_t>(lapicCount); // IOAPIC id
    Put32(io, 4, 0xFEC00000);               // IOAPIC address
    Put32(io, 8, 0);                        // GSI base
    m.insert(m.end(), io.begin(), io.end());

    FinishTable(m, "APIC");
    return m;
}

// FADT v6 (length 276). Cross-refs (FACS/DSDT) are patched by the
// caller once GPAs are assigned.
std::vector<uint8_t> BuildFadt()
{
    std::vector<uint8_t> f(276, 0);
    f[8] = 6;                                  // FADT major revision
    std::memcpy(f.data() + 46, "\x09\x00", 2); // SCI_INT = 9 (u16)
    f[131] = 0;                                // FADT minor revision
    // Flags (offset 112): HW_REDUCED_ACPI off; leave zero — the
    // kernel treats a legacy FADT as the common case. FIRMWARE_CTRL
    // (36) / DSDT (40) / X_FIRMWARE_CTRL (132) / X_DSDT (140) are
    // patched by the caller once GPAs are known.
    return f;            // signature/length/checksum via FinishTable
}

} // namespace

AcpiImage BuildAcpi(uint64_t baseGpa, uint32_t lapicCount)
{
    auto facs = BuildFacs();
    auto dsdt = BuildDsdt();
    auto madt = BuildMadt(lapicCount);
    auto fadt = BuildFadt();

    // Layout order in the blob; each 16-byte aligned.
    auto align16 = [](uint64_t x) { return (x + 15) & ~uint64_t(15); };

    uint64_t facsGpa = align16(baseGpa);
    uint64_t dsdtGpa = align16(facsGpa + facs.size());
    uint64_t madtGpa = align16(dsdtGpa + dsdt.size());
    uint64_t fadtGpa = align16(madtGpa + madt.size());
    uint64_t xsdtGpa = align16(fadtGpa + fadt.size());

    // Patch FADT cross-references now that FACS/DSDT GPAs are known.
    Put32(fadt, 36, static_cast<uint32_t>(facsGpa)); // FIRMWARE_CTRL
    Put32(fadt, 40, static_cast<uint32_t>(dsdtGpa)); // DSDT
    Put64(fadt, 132, facsGpa);                       // X_FIRMWARE_CTRL
    Put64(fadt, 140, dsdtGpa);                       // X_DSDT
    FinishTable(fadt, "FACP");

    // XSDT: header + 64-bit pointers to FADT and MADT.
    std::vector<uint8_t> xsdt(36 + 2 * 8, 0);
    Put64(xsdt, 36, fadtGpa);
    Put64(xsdt, 44, madtGpa);
    FinishTable(xsdt, "XSDT");

    // Assemble the blob in GPA order, padding to the aligned offsets.
    AcpiImage img;
    img.baseGpa = baseGpa;
    auto append = [&](uint64_t gpa, const std::vector<uint8_t>& t) {
        uint64_t off = gpa - baseGpa;
        if (img.blob.size() < off)
        {
            img.blob.resize(off, 0);
        }
        img.blob.insert(img.blob.end(), t.begin(), t.end());
    };
    append(facsGpa, facs);
    append(dsdtGpa, dsdt);
    append(madtGpa, madt);
    append(fadtGpa, fadt);
    append(xsdtGpa, xsdt);

    // RSDP (ACPI 2.0, 36 bytes) — embedded into the Multiboot2 tag.
    img.rsdp.assign(36, 0);
    std::memcpy(img.rsdp.data(), "RSD PTR ", 8);
    std::memcpy(img.rsdp.data() + 9, "DUETOS", 6); // OEMID
    img.rsdp[15] = 2;                              // Revision (ACPI 2.0)
    Put32(img.rsdp, 16, 0);                        // RsdtAddress (none)
    Put32(img.rsdp, 20, 36);                       // RSDP length
    Put64(img.rsdp, 24, xsdtGpa);                  // XsdtAddress
    img.rsdp[8] = Checksum(img.rsdp.data(), 20);   // legacy checksum
    img.rsdp[32] = Checksum(img.rsdp.data(), 36);  // extended checksum
    return img;
}

} // namespace duetos::vmm
