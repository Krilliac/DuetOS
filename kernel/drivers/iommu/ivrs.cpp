#include "drivers/iommu/ivrs.h"

#include "acpi/acpi.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::iommu
{

namespace
{

constinit ivrs::DuetosIvrs g_ivrs{};
constinit bool g_initialized = false;

void SerialWriteHex64(u64 v)
{
    char buf[19] = {'0', 'x'};
    for (int i = 0; i < 16; ++i)
    {
        const u8 nibble = (v >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10);
    }
    buf[18] = 0;
    arch::SerialWrite(buf);
}

void SerialWriteDec(u32 v)
{
    char buf[12] = {0};
    if (v == 0)
    {
        buf[0] = '0';
        arch::SerialWrite(buf);
        return;
    }
    char rev[12];
    int rl = 0;
    while (v)
    {
        rev[rl++] = '0' + (v % 10);
        v /= 10;
    }
    int bi = 0;
    while (rl > 0)
        buf[bi++] = rev[--rl];
    arch::SerialWrite(buf);
}

} // namespace

void IvrsInit()
{
    if (g_initialized)
        return;
    g_initialized = true;

    u64 phys = 0;
    u32 len = 0;
    if (!acpi::AcpiFindTablePhys("IVRS", &phys, &len))
    {
        arch::SerialWrite("[ivrs] present=no (table absent)\n");
        return;
    }

    const void* mapped = acpi::AcpiMapTable(phys, len);
    if (mapped == nullptr || len == 0)
    {
        arch::SerialWrite("[ivrs] present=no (mapping failed)\n");
        return;
    }

    if (!ivrs::duetos_ivrs_parse(reinterpret_cast<const u8*>(mapped), len, &g_ivrs))
    {
        arch::SerialWrite("[ivrs] present=no (parse rejected the table)\n");
        ivrs::duetos_ivrs_zero(&g_ivrs);
        return;
    }

    arch::SerialWrite("[ivrs] present=yes iv_info=");
    SerialWriteHex64(g_ivrs.iv_info);
    arch::SerialWrite(" ivhds=");
    SerialWriteDec(g_ivrs.n_ivhds);
    arch::SerialWrite(" ivmds=");
    SerialWriteDec(g_ivrs.n_ivmds);
    arch::SerialWrite("\n");

    for (u32 i = 0; i < g_ivrs.n_ivhds; ++i)
    {
        arch::SerialWrite("[ivrs] ivhd[");
        SerialWriteDec(i);
        arch::SerialWrite("] type=");
        SerialWriteHex64(g_ivrs.ivhds[i].block_type);
        arch::SerialWrite(" base=");
        SerialWriteHex64(g_ivrs.ivhds[i].iommu_base_address);
        arch::SerialWrite(" segment=");
        SerialWriteDec(g_ivrs.ivhds[i].pci_segment);
        arch::SerialWrite(" devid=");
        SerialWriteHex64(g_ivrs.ivhds[i].device_id);
        if (g_ivrs.ivhds[i].efr_register_image != 0)
        {
            arch::SerialWrite(" efr=");
            SerialWriteHex64(g_ivrs.ivhds[i].efr_register_image);
        }
        arch::SerialWrite("\n");
    }
}

bool IvrsPresent()
{
    return g_initialized && g_ivrs.ok != 0;
}

u32 IvrsInfo()
{
    return IvrsPresent() ? g_ivrs.iv_info : 0;
}

u32 IvrsIvhdCount()
{
    return IvrsPresent() ? g_ivrs.n_ivhds : 0;
}

const ivrs::DuetosIvrsIvhd* IvrsIvhd(u32 index)
{
    if (!IvrsPresent() || index >= g_ivrs.n_ivhds)
        return nullptr;
    return &g_ivrs.ivhds[index];
}

u32 IvrsIvmdCount()
{
    return IvrsPresent() ? g_ivrs.n_ivmds : 0;
}

const ivrs::DuetosIvrsIvmd* IvrsIvmd(u32 index)
{
    if (!IvrsPresent() || index >= g_ivrs.n_ivmds)
        return nullptr;
    return &g_ivrs.ivmds[index];
}

void IvrsSelfTest()
{
    // Synthesise an IVRS in stack memory: 48-byte header
    // (36-byte SDT + 12-byte IVRS-specific) + 1 fixed IVHD
    // (type 0x10) + 1 extended IVHD (type 0x11) + 1 IVMD.
    constexpr u32 kBufBytes = 512;
    u8 buf[kBufBytes] = {};

    buf[0] = 'I';
    buf[1] = 'V';
    buf[2] = 'R';
    buf[3] = 'S';
    buf[8] = 1; // revision
    buf[9] = 0; // checksum (parser doesn't validate)
    // IVinfo at offset 36
    buf[36] = 0x02;
    buf[37] = 0x00;
    buf[38] = 0x01;
    buf[39] = 0x00;

    u32 off = 48;

    // IVHD fixed (type 0x10, 24 bytes).
    buf[off + 0] = ivrs::kIvrsTypeIvhdFixed;
    buf[off + 1] = 0x55; // flags
    buf[off + 2] = 24;   // length lo
    buf[off + 3] = 0;
    // iommu_base = 0xFEB80000
    buf[off + 8] = 0x00;
    buf[off + 9] = 0x00;
    buf[off + 10] = 0xB8;
    buf[off + 11] = 0xFE;
    buf[off + 12] = 0x00;
    buf[off + 13] = 0x00;
    buf[off + 14] = 0x00;
    buf[off + 15] = 0x00;
    off += 24;

    // IVHD extended (type 0x11, 40 bytes) with EFR=0x123456789ABCDEF.
    buf[off + 0] = ivrs::kIvrsTypeIvhdExtended;
    buf[off + 1] = 0xAA;
    buf[off + 2] = 40;
    buf[off + 3] = 0;
    buf[off + 8] = 0x00;
    buf[off + 9] = 0x10;
    buf[off + 10] = 0xB8;
    buf[off + 11] = 0xFE;
    // EFR at +24
    buf[off + 24] = 0xEF;
    buf[off + 25] = 0xCD;
    buf[off + 26] = 0xAB;
    buf[off + 27] = 0x89;
    buf[off + 28] = 0x67;
    buf[off + 29] = 0x45;
    buf[off + 30] = 0x23;
    buf[off + 31] = 0x01;
    off += 40;

    // IVMD (type 0x20, 32 bytes). Region 0xC0000..0xD0000.
    buf[off + 0] = ivrs::kIvrsTypeIvmdAll;
    buf[off + 2] = 32;
    buf[off + 3] = 0;
    // start_address at +16, memory_length at +24
    buf[off + 16] = 0x00;
    buf[off + 17] = 0x00;
    buf[off + 18] = 0x0C;
    buf[off + 19] = 0x00;
    buf[off + 24] = 0x00;
    buf[off + 25] = 0x00;
    buf[off + 26] = 0x01;
    buf[off + 27] = 0x00;
    off += 32;

    const u32 table_len = off;
    buf[4] = table_len & 0xFF;
    buf[5] = (table_len >> 8) & 0xFF;
    buf[6] = (table_len >> 16) & 0xFF;
    buf[7] = (table_len >> 24) & 0xFF;

    const ivrs::DuetosIvrs saved = g_ivrs;
    const bool saved_init = g_initialized;

    ivrs::DuetosIvrs tmp{};
    KASSERT(ivrs::duetos_ivrs_parse(buf, table_len, &tmp), "drivers/iommu/ivrs", "synthetic IVRS parse failed");
    KASSERT(tmp.ok == 1, "drivers/iommu/ivrs", "ok flag not set");
    KASSERT(tmp.iv_info == 0x00010002, "drivers/iommu/ivrs", "IVinfo decode wrong");
    KASSERT(tmp.n_ivhds == 2, "drivers/iommu/ivrs", "IVHD count wrong");
    KASSERT(tmp.ivhds[0].block_type == ivrs::kIvrsTypeIvhdFixed, "drivers/iommu/ivrs", "IVHD[0] type wrong");
    KASSERT(tmp.ivhds[0].flags == 0x55, "drivers/iommu/ivrs", "IVHD[0] flags round-trip wrong");
    KASSERT(tmp.ivhds[0].iommu_base_address == 0xFEB80000ull, "drivers/iommu/ivrs", "IVHD[0] base round-trip wrong");
    KASSERT(tmp.ivhds[0].efr_register_image == 0, "drivers/iommu/ivrs", "IVHD[0] (type 0x10) should not have EFR");
    KASSERT(tmp.ivhds[1].block_type == ivrs::kIvrsTypeIvhdExtended, "drivers/iommu/ivrs", "IVHD[1] type wrong");
    KASSERT(tmp.ivhds[1].iommu_base_address == 0xFEB81000ull, "drivers/iommu/ivrs", "IVHD[1] base round-trip wrong");
    KASSERT(tmp.ivhds[1].efr_register_image == 0x0123456789ABCDEFull, "drivers/iommu/ivrs",
            "IVHD[1] EFR round-trip wrong");
    KASSERT(tmp.n_ivmds == 1, "drivers/iommu/ivrs", "IVMD count wrong");
    KASSERT(tmp.ivmds[0].start_address == 0x000C0000ull, "drivers/iommu/ivrs", "IVMD start round-trip wrong");
    KASSERT(tmp.ivmds[0].memory_length == 0x10000ull, "drivers/iommu/ivrs", "IVMD length round-trip wrong");

    // Bad signature.
    u8 bad[64] = {};
    bad[0] = 'X';
    bad[1] = 'V';
    bad[2] = 'R';
    bad[3] = 'S';
    KASSERT(!ivrs::duetos_ivrs_parse(bad, sizeof(bad), &tmp), "drivers/iommu/ivrs", "bad signature accepted");

    g_ivrs = saved;
    g_initialized = saved_init;

    arch::SerialWrite("[ivrs-selftest] PASS\n");
}

} // namespace duetos::drivers::iommu
