#include "drivers/iommu/dmar.h"

#include "acpi/acpi.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::drivers::iommu
{

namespace
{

constinit dmar::DuetosDmar g_dmar{};
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

void DmarInit()
{
    if (g_initialized)
        return;
    g_initialized = true;

    u64 phys = 0;
    u32 len = 0;
    if (!acpi::AcpiFindTablePhys("DMAR", &phys, &len))
    {
        arch::SerialWrite("[dmar] present=no (table absent)\n");
        return;
    }

    const void* mapped = acpi::AcpiMapTable(phys, len);
    if (mapped == nullptr || len == 0)
    {
        arch::SerialWrite("[dmar] present=no (mapping failed)\n");
        return;
    }

    if (!dmar::duetos_dmar_parse(reinterpret_cast<const u8*>(mapped), len, &g_dmar))
    {
        arch::SerialWrite("[dmar] present=no (parse rejected the table)\n");
        // Zero the struct so accessors return safe defaults.
        dmar::duetos_dmar_zero(&g_dmar);
        return;
    }

    arch::SerialWrite("[dmar] present=yes haw=");
    SerialWriteDec(g_dmar.host_address_width);
    arch::SerialWrite(" drhds=");
    SerialWriteDec(g_dmar.n_drhds);
    arch::SerialWrite(" rmrrs=");
    SerialWriteDec(g_dmar.n_rmrrs);
    arch::SerialWrite(" flags=");
    SerialWriteHex64(g_dmar.flags);
    arch::SerialWrite("\n");

    for (u32 i = 0; i < g_dmar.n_drhds; ++i)
    {
        arch::SerialWrite("[dmar] drhd[");
        SerialWriteDec(i);
        arch::SerialWrite("] base=");
        SerialWriteHex64(g_dmar.drhds[i].register_base);
        arch::SerialWrite(" segment=");
        SerialWriteDec(g_dmar.drhds[i].segment);
        arch::SerialWrite(" flags=");
        SerialWriteHex64(g_dmar.drhds[i].flags);
        arch::SerialWrite("\n");
    }
}

bool DmarPresent()
{
    return g_initialized && g_dmar.ok != 0;
}

u8 DmarHostAddressWidth()
{
    return DmarPresent() ? g_dmar.host_address_width : 0;
}

u8 DmarHeaderFlags()
{
    return DmarPresent() ? g_dmar.flags : 0;
}

u32 DmarDrhdCount()
{
    return DmarPresent() ? g_dmar.n_drhds : 0;
}

const dmar::DuetosDmarDrhd* DmarDrhd(u32 index)
{
    if (!DmarPresent() || index >= g_dmar.n_drhds)
        return nullptr;
    return &g_dmar.drhds[index];
}

u32 DmarRmrrCount()
{
    return DmarPresent() ? g_dmar.n_rmrrs : 0;
}

const dmar::DuetosDmarRmrr* DmarRmrr(u32 index)
{
    if (!DmarPresent() || index >= g_dmar.n_rmrrs)
        return nullptr;
    return &g_dmar.rmrrs[index];
}

void DmarSelfTest()
{
    // Synthesise a small DMAR in stack memory: 48-byte header
    // (36-byte SDT + 12-byte DMAR-specific) + one DRHD + one RMRR.
    constexpr u32 kBufBytes = 256;
    u8 buf[kBufBytes] = {};

    // SDT header.
    buf[0] = 'D';
    buf[1] = 'M';
    buf[2] = 'A';
    buf[3] = 'R';
    // table length filled in below
    buf[8] = 1;     // revision
    buf[9] = 0;     // checksum (not validated by Rust parser — Acpi C++ side does that)
    buf[36] = 39;   // HAW
    buf[37] = 0x01; // INTR_REMAP

    u32 off = 48;
    // DRHD entry (16 bytes fixed; no device-scope after).
    buf[off + 0] = dmar::kDmarTypeDrhd & 0xFF;
    buf[off + 1] = (dmar::kDmarTypeDrhd >> 8) & 0xFF;
    buf[off + 2] = 16; // length lo
    buf[off + 3] = 0;
    buf[off + 4] = dmar::kDmarDrhdFlagIncludePciAll;
    buf[off + 6] = 0; // segment
    buf[off + 7] = 0;
    // register_base = 0xFED90000
    buf[off + 8] = 0x00;
    buf[off + 9] = 0x00;
    buf[off + 10] = 0xD9;
    buf[off + 11] = 0xFE;
    buf[off + 12] = 0x00;
    buf[off + 13] = 0x00;
    buf[off + 14] = 0x00;
    buf[off + 15] = 0x00;
    off += 16;

    // RMRR entry (24 bytes fixed; no device-scope after).
    buf[off + 0] = dmar::kDmarTypeRmrr & 0xFF;
    buf[off + 1] = (dmar::kDmarTypeRmrr >> 8) & 0xFF;
    buf[off + 2] = 24;
    buf[off + 3] = 0;
    // segment = 0
    // base = 0x000A0000
    buf[off + 8] = 0x00;
    buf[off + 9] = 0x00;
    buf[off + 10] = 0x0A;
    buf[off + 11] = 0x00;
    // limit = 0x000BFFFF
    buf[off + 16] = 0xFF;
    buf[off + 17] = 0xFF;
    buf[off + 18] = 0x0B;
    buf[off + 19] = 0x00;
    off += 24;

    // Patch table length.
    const u32 table_len = off;
    buf[4] = table_len & 0xFF;
    buf[5] = (table_len >> 8) & 0xFF;
    buf[6] = (table_len >> 16) & 0xFF;
    buf[7] = (table_len >> 24) & 0xFF;

    // Save live state, run parse, restore.
    const dmar::DuetosDmar saved = g_dmar;
    const bool saved_init = g_initialized;

    dmar::DuetosDmar tmp{};
    KASSERT(dmar::duetos_dmar_parse(buf, table_len, &tmp), "drivers/iommu", "synthetic DMAR parse failed");
    KASSERT(tmp.ok == 1, "drivers/iommu", "ok flag not set");
    KASSERT(tmp.host_address_width == 39, "drivers/iommu", "HAW round-trip wrong");
    KASSERT(tmp.flags == 0x01, "drivers/iommu", "header flags round-trip wrong");
    KASSERT(tmp.n_drhds == 1, "drivers/iommu", "DRHD count wrong");
    KASSERT(tmp.drhds[0].register_base == 0xFED90000ull, "drivers/iommu", "DRHD base round-trip wrong");
    KASSERT(tmp.drhds[0].flags == dmar::kDmarDrhdFlagIncludePciAll, "drivers/iommu", "DRHD flags round-trip wrong");
    KASSERT(tmp.n_rmrrs == 1, "drivers/iommu", "RMRR count wrong");
    KASSERT(tmp.rmrrs[0].base_address == 0x000A0000ull, "drivers/iommu", "RMRR base round-trip wrong");
    KASSERT(tmp.rmrrs[0].limit_address == 0x000BFFFFull, "drivers/iommu", "RMRR limit round-trip wrong");

    // Bad signature must reject.
    u8 bad[64] = {};
    bad[0] = 'X';
    bad[1] = 'M';
    bad[2] = 'A';
    bad[3] = 'R';
    KASSERT(!dmar::duetos_dmar_parse(bad, sizeof(bad), &tmp), "drivers/iommu", "bad signature accepted");

    // Restore live state.
    g_dmar = saved;
    g_initialized = saved_init;

    arch::SerialWrite("[dmar-selftest] PASS\n");
}

} // namespace duetos::drivers::iommu
