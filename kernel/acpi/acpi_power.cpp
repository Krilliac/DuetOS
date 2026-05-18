/*
 * DuetOS — ACPI power-device evaluators (v0): implementation.
 * See acpi_power.h for the device-discovery model and GAPs.
 */

#include "acpi/acpi_power.h"

#include "acpi/aml.h"
#include "acpi/aml_eval.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::acpi
{

namespace
{

u32 SLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

bool EndsWith(const char* s, const char* suffix)
{
    const u32 ls = SLen(s);
    const u32 lf = SLen(suffix);
    if (lf > ls)
        return false;
    for (u32 i = 0; i < lf; ++i)
        if (s[ls - lf + i] != suffix[i])
            return false;
    return true;
}

// Find the first Method whose leaf is `suffix` (e.g. "._BST") and
// copy its owning device path (path minus suffix) into `out`.
bool FindDeviceByMethod(const char* suffix, char* out, u32 cap)
{
    const u32 n = AmlNamespaceCount();
    const u32 lf = SLen(suffix);
    for (u32 i = 0; i < n; ++i)
    {
        const AmlNamespaceEntry* e = AmlNamespaceEntryAt(i);
        if (e == nullptr || e->kind != AmlObjectKind::Method)
            continue;
        if (!EndsWith(e->path, suffix))
            continue;
        const u32 lp = SLen(e->path);
        const u32 keep = lp - lf;
        if (keep + 1 > cap || keep == 0)
            return false;
        for (u32 k = 0; k < keep; ++k)
            out[k] = e->path[k];
        out[keep] = '\0';
        return true;
    }
    return false;
}

// dev + leaf → "dev.leaf" (leaf already includes its underscore,
// e.g. "_BIF"). Returns false on overflow.
bool MakePath(const char* dev, const char* leaf, char* out, u32 cap)
{
    u32 w = 0;
    for (; dev[w] != '\0'; ++w)
    {
        if (w + 1 >= cap)
            return false;
        out[w] = dev[w];
    }
    if (w + 1 >= cap)
        return false;
    out[w++] = '.';
    for (u32 i = 0; leaf[i] != '\0'; ++i)
    {
        if (w + 1 >= cap)
            return false;
        out[w++] = leaf[i];
    }
    out[w] = '\0';
    return true;
}

constexpr u32 kUnknown32 = 0xFFFFFFFFu; // ACPI "unknown" sentinel

} // namespace

bool AcpiReadBattery(AcpiBatteryReading* out)
{
    if (out == nullptr)
        return false;
    *out = AcpiBatteryReading{};
    out->status = AcpiBatStatus::Unknown;
    out->percent = 255;

    char dev[64];
    if (!FindDeviceByMethod("._BST", dev, sizeof(dev)))
        return false;

    char path[80];

    // _STA: bit 4 (0x10) = battery present. Absent _STA ⇒ present.
    if (MakePath(dev, "_STA", path, sizeof(path)))
    {
        u64 sta = 0;
        if (AmlEvaluateInteger(path, &sta) && (sta & 0x10) == 0)
        {
            out->status = AcpiBatStatus::NotPresent;
            out->percent = 0;
            return true;
        }
    }

    u64 bif[16] = {};
    u32 bif_n = 0;
    if (!MakePath(dev, "_BIF", path, sizeof(path)) || !AmlEvaluatePackageInts(path, bif, 16, &bif_n) || bif_n < 5)
        return false;
    const u64 power_unit = bif[0];        // 0 = mW(h), 1 = mA(h)
    const u64 design_cap = bif[1];        // mWh or mAh
    const u64 last_full = bif[2];         // mWh or mAh
    const u64 design_voltage_mv = bif[4]; // mV

    u64 bst[8] = {};
    u32 bst_n = 0;
    if (!MakePath(dev, "_BST", path, sizeof(path)) || !AmlEvaluatePackageInts(path, bst, 8, &bst_n) || bst_n < 4)
        return false;
    const u64 bst_state = bst[0];     // bit0 discharging, bit1 charging
    const u64 bst_rate = bst[1];      // mW or mA
    const u64 bst_remaining = bst[2]; // mWh or mAh
    const u64 bst_voltage = bst[3];   // mV

    const u32 volt_mv = (bst_voltage != 0 && bst_voltage != kUnknown32) ? u32(bst_voltage) : u32(design_voltage_mv);
    out->voltage_mv = (volt_mv == kUnknown32) ? 0 : volt_mv;

    // Normalise capacity/rate to mW(h). For mA-based batteries scale
    // by voltage (approximate — GAP noted in the header).
    auto to_mwh = [&](u64 v) -> u32
    {
        if (v == kUnknown32 || v == 0)
            return 0;
        if (power_unit == 1) // mAh → mWh
            return u32((v * (volt_mv == kUnknown32 ? 0 : volt_mv)) / 1000);
        return u32(v);
    };
    out->design_mwh = to_mwh(design_cap);
    out->full_mwh = to_mwh(last_full);

    const u32 rem_mwh = to_mwh(bst_remaining);
    out->percent = out->full_mwh
                       ? u8((u64(rem_mwh) * 100) / out->full_mwh > 100 ? 100 : (u64(rem_mwh) * 100) / out->full_mwh)
                       : 255;

    i64 rate_mw = 0;
    if (bst_rate != kUnknown32)
        rate_mw = (power_unit == 1) ? i64((bst_rate * (volt_mv == kUnknown32 ? 0 : volt_mv)) / 1000) : i64(bst_rate);

    if (bst_state & 0x01) // discharging
    {
        out->status = AcpiBatStatus::Discharging;
        out->rate_mw = i32(-rate_mw);
    }
    else if (bst_state & 0x02) // charging
    {
        out->status = AcpiBatStatus::Charging;
        out->rate_mw = i32(rate_mw);
    }
    else if (out->percent != 255 && out->percent >= 95)
    {
        out->status = AcpiBatStatus::Full;
        out->rate_mw = 0;
    }
    else
    {
        out->status = AcpiBatStatus::Unknown;
        out->rate_mw = 0;
    }
    return true;
}

bool AcpiReadAcOnline(bool* online)
{
    if (online == nullptr)
        return false;
    char dev[64];
    if (!FindDeviceByMethod("._PSR", dev, sizeof(dev)))
        return false;
    char path[80];
    u64 v = 0;
    if (!MakePath(dev, "_PSR", path, sizeof(path)) || !AmlEvaluateInteger(path, &v))
        return false;
    *online = (v != 0);
    return true;
}

bool AcpiReadLid(bool* open)
{
    if (open == nullptr)
        return false;
    char dev[64];
    if (!FindDeviceByMethod("._LID", dev, sizeof(dev)))
        return false;
    char path[80];
    u64 v = 0;
    if (!MakePath(dev, "_LID", path, sizeof(path)) || !AmlEvaluateInteger(path, &v))
        return false;
    *open = (v != 0);
    return true;
}

bool AcpiBacklightLevels(u32* levels, u32 cap, u32* count)
{
    if (levels == nullptr || count == nullptr)
        return false;
    *count = 0;
    char dev[64];
    if (!FindDeviceByMethod("._BCL", dev, sizeof(dev)))
        return false;
    char path[80];
    u64 raw[64] = {};
    u32 n = 0;
    if (!MakePath(dev, "_BCL", path, sizeof(path)) || !AmlEvaluatePackageInts(path, raw, 64, &n))
        return false;
    // _BCL: [0]=level on full power, [1]=level on battery, [2..]=the
    // actual selectable levels. Surface only the selectable list.
    u32 w = 0;
    for (u32 i = 2; i < n && w < cap; ++i)
        levels[w++] = u32(raw[i]);
    *count = w;
    return w != 0;
}

bool AcpiBacklightGet(u32* level)
{
    if (level == nullptr)
        return false;
    char dev[64];
    if (!FindDeviceByMethod("._BQC", dev, sizeof(dev)))
        return false;
    char path[80];
    u64 v = 0;
    if (!MakePath(dev, "_BQC", path, sizeof(path)) || !AmlEvaluateInteger(path, &v))
        return false;
    *level = u32(v);
    return true;
}

bool AcpiBacklightSet(u32 level)
{
    char dev[64];
    if (!FindDeviceByMethod("._BCM", dev, sizeof(dev)))
        return false;
    char path[80];
    if (!MakePath(dev, "_BCM", path, sizeof(path)))
        return false;
    AmlValue arg = AmlValue::Int(level);
    AmlValue r;
    return AmlEvaluate(path, &arg, 1, &r).has_value();
}

void AcpiPowerSelfTest()
{
    // The decode path must run without faulting whether or not the
    // firmware declares power devices. On QEMU all of these return
    // false (no _BST/_PSR/_LID) and leave their outputs untouched.
    AcpiBatteryReading b{};
    const bool have_bat = AcpiReadBattery(&b);
    bool ac = false, lid = false;
    const bool have_ac = AcpiReadAcOnline(&ac);
    const bool have_lid = AcpiReadLid(&lid);

    if (have_bat && b.percent != 255 && b.percent > 100)
        core::PanicWithValue("acpi/power", "selftest: battery percent out of range", b.percent);

    arch::SerialWrite("[acpi/power] selftest PASS (battery=");
    arch::SerialWrite(have_bat ? "read" : "absent");
    arch::SerialWrite(" ac=");
    arch::SerialWrite(have_ac ? "read" : "absent");
    arch::SerialWrite(" lid=");
    arch::SerialWrite(have_lid ? "read" : "absent");
    arch::SerialWrite(")\n");
    KLOG_INFO_V("acpi/power", "selftest PASS — battery readable?", have_bat ? 1 : 0);
}

} // namespace duetos::acpi
