#include "drivers/audio/hda_jack_inventory.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/spinlock.h"

namespace duetos::drivers::audio::hda
{

namespace
{

struct InventoryState
{
    HdaJackRecord records[kHdaJackInventoryCap];
    u32 count;
};

constinit InventoryState g_inv{};
constinit duetos::sync::SpinLock g_inv_lock{};

i32 FindIndex(u8 codec_slot, u8 pin_node)
{
    for (u32 i = 0; i < kHdaJackInventoryCap; ++i)
    {
        if (!g_inv.records[i].live)
            continue;
        if (g_inv.records[i].codec_slot == codec_slot && g_inv.records[i].pin_node == pin_node)
            return static_cast<i32>(i);
    }
    return -1;
}

void EqU64(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[hda-inventory] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/audio/hda-inventory", "inventory self-test mismatch", actual);
}

} // namespace

void HdaJackInventoryReset()
{
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);
    for (u32 i = 0; i < kHdaJackInventoryCap; ++i)
        g_inv.records[i] = {};
    g_inv.count = 0;
    duetos::sync::SpinLockRelease(g_inv_lock, flags);
}

bool HdaJackInventoryRecord(u8 codec_slot, u8 pin_node, u32 config_default_raw)
{
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);

    // Replace existing record for the same (codec, pin) to keep
    // the inventory idempotent across re-walks.
    const i32 existing = FindIndex(codec_slot, pin_node);
    if (existing >= 0)
    {
        g_inv.records[existing].config = HdaDecodePinConfigDefault(config_default_raw);
        g_inv.records[existing].jack_present_known = false;
        g_inv.records[existing].jack_present = false;
        duetos::sync::SpinLockRelease(g_inv_lock, flags);
        return true;
    }

    for (u32 i = 0; i < kHdaJackInventoryCap; ++i)
    {
        if (g_inv.records[i].live)
            continue;
        g_inv.records[i].live = true;
        g_inv.records[i].codec_slot = codec_slot;
        g_inv.records[i].pin_node = pin_node;
        g_inv.records[i].config = HdaDecodePinConfigDefault(config_default_raw);
        g_inv.records[i].jack_present_known = false;
        g_inv.records[i].jack_present = false;
        ++g_inv.count;
        duetos::sync::SpinLockRelease(g_inv_lock, flags);
        return true;
    }

    duetos::sync::SpinLockRelease(g_inv_lock, flags);
    return false;
}

void HdaJackInventoryStampPresence(u8 codec_slot, u8 pin_node, u32 pin_sense_response)
{
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);
    const i32 idx = FindIndex(codec_slot, pin_node);
    if (idx >= 0)
    {
        g_inv.records[idx].jack_present_known = true;
        g_inv.records[idx].jack_present = HdaJackPresent(pin_sense_response);
    }
    duetos::sync::SpinLockRelease(g_inv_lock, flags);
}

u32 HdaJackInventoryCount()
{
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);
    const u32 count = g_inv.count;
    duetos::sync::SpinLockRelease(g_inv_lock, flags);
    return count;
}

bool HdaJackInventoryRead(u32 index, HdaJackRecord* out)
{
    if (out == nullptr)
        return false;
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);
    u32 logical = 0;
    for (u32 i = 0; i < kHdaJackInventoryCap; ++i)
    {
        if (!g_inv.records[i].live)
            continue;
        if (logical == index)
        {
            *out = g_inv.records[i];
            duetos::sync::SpinLockRelease(g_inv_lock, flags);
            return true;
        }
        ++logical;
    }
    duetos::sync::SpinLockRelease(g_inv_lock, flags);
    return false;
}

bool HdaJackInventoryFindByDevice(HdaDefaultDevice target, u8* codec_slot_out, u8* pin_node_out)
{
    auto flags = duetos::sync::SpinLockAcquire(g_inv_lock);
    for (u32 i = 0; i < kHdaJackInventoryCap; ++i)
    {
        if (!g_inv.records[i].live)
            continue;
        if (g_inv.records[i].config.default_device != target)
            continue;
        // Skip pins with no physical connection — they exist in
        // the codec but the board didn't wire them, so they
        // cannot drive sound.
        if (g_inv.records[i].config.port_connectivity == HdaPortConnectivity::NoPhysicalConn)
            continue;
        if (codec_slot_out != nullptr)
            *codec_slot_out = g_inv.records[i].codec_slot;
        if (pin_node_out != nullptr)
            *pin_node_out = g_inv.records[i].pin_node;
        duetos::sync::SpinLockRelease(g_inv_lock, flags);
        return true;
    }
    duetos::sync::SpinLockRelease(g_inv_lock, flags);
    return false;
}

void HdaJackInventorySelfTest()
{
    HdaJackInventoryReset();
    EqU64(HdaJackInventoryCount(), 0, "empty count");

    // Same canonical configs as hda_jack_selftest, populated
    // through the inventory path.
    EqU64(u64(HdaJackInventoryRecord(0, 0x14, 0x01014010u) ? 1 : 0), 1, "record line-out");
    EqU64(u64(HdaJackInventoryRecord(0, 0x15, 0x90100010u) ? 1 : 0), 1, "record speaker");
    EqU64(u64(HdaJackInventoryRecord(0, 0x18, 0x02A19020u) ? 1 : 0), 1, "record mic");
    EqU64(u64(HdaJackInventoryRecord(0, 0x19, 0x40000000u) ? 1 : 0), 1, "record no-conn");
    EqU64(HdaJackInventoryCount(), 4, "count=4 after 4 records");

    // Idempotent re-record: replacing pin 0x14 with a different
    // dword must not grow the count.
    EqU64(u64(HdaJackInventoryRecord(0, 0x14, 0x01014020u) ? 1 : 0), 1, "re-record line-out");
    EqU64(HdaJackInventoryCount(), 4, "count stays 4");

    // Read each record back and assert the decoded fields.
    HdaJackRecord r{};
    EqU64(u64(HdaJackInventoryRead(0, &r) ? 1 : 0), 1, "read[0]");
    EqU64(r.pin_node, 0x14, "read[0] pin");
    EqU64(static_cast<u64>(r.config.default_device), static_cast<u64>(HdaDefaultDevice::LineOut), "read[0] device");

    EqU64(u64(HdaJackInventoryRead(1, &r) ? 1 : 0), 1, "read[1]");
    EqU64(static_cast<u64>(r.config.default_device), static_cast<u64>(HdaDefaultDevice::Speaker), "read[1] device");

    // Find-by-device must skip the no-conn record and the wrong-
    // device records.
    u8 codec = 0xFF;
    u8 pin = 0xFF;
    EqU64(u64(HdaJackInventoryFindByDevice(HdaDefaultDevice::Speaker, &codec, &pin) ? 1 : 0), 1, "find speaker");
    EqU64(codec, 0, "find speaker codec");
    EqU64(pin, 0x15, "find speaker pin");

    EqU64(u64(HdaJackInventoryFindByDevice(HdaDefaultDevice::HpOut, &codec, &pin) ? 1 : 0), 0, "no hp pin");

    // Stamp presence on the line-out and verify accessor.
    HdaJackInventoryStampPresence(0, 0x14, /*GET_PIN_SENSE=*/0x80000000u);
    EqU64(u64(HdaJackInventoryRead(0, &r) ? 1 : 0), 1, "read[0] after presence");
    EqU64(u64(r.jack_present_known ? 1 : 0), 1, "presence known");
    EqU64(u64(r.jack_present ? 1 : 0), 1, "presence true");

    HdaJackInventoryStampPresence(0, 0x14, 0x00000000u);
    EqU64(u64(HdaJackInventoryRead(0, &r) ? 1 : 0), 1, "read[0] after toggle");
    EqU64(u64(r.jack_present ? 1 : 0), 0, "presence cleared");

    // Read past end must return false.
    EqU64(u64(HdaJackInventoryRead(99, &r) ? 1 : 0), 0, "out-of-range read");

    // Reset clears everything.
    HdaJackInventoryReset();
    EqU64(HdaJackInventoryCount(), 0, "count after reset");

    arch::SerialWrite("[hda-inventory] selftest pass\n");
}

} // namespace duetos::drivers::audio::hda
