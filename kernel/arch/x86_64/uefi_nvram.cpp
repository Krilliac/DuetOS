#include "arch/x86_64/uefi_nvram.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "mm/frame_allocator.h"
#include "mm/multiboot2.h"
#include "mm/paging.h"

namespace duetos::arch
{

namespace
{

// Multiboot2 EFI64 system-table tag. Not in mm/multiboot2.h (the frame
// allocator doesn't consume it), so spelled out here.
constexpr u32 kMultibootTagEfi64SystemTable = 12;

// "IBI SYST" little-endian — EFI_SYSTEM_TABLE.Hdr.Signature.
constexpr u64 kEfiSystemTableSignature = 0x5453595320494249ULL;

struct [[gnu::packed]] EfiTableHeader
{
    u64 signature;
    u32 revision;
    u32 header_size;
    u32 crc32;
    u32 reserved;
};

// x86_64 EFI_SYSTEM_TABLE — only the head fields v0 reads. Field offsets
// match the UEFI spec (RuntimeServices at offset 88, BootServices at 96).
struct [[gnu::packed]] EfiSystemTable
{
    EfiTableHeader hdr;          // 0
    u64 firmware_vendor;         // 24  CHAR16*
    u32 firmware_revision;       // 32
    u32 pad0;                    // 36
    u64 console_in_handle;       // 40
    u64 con_in;                  // 48
    u64 console_out_handle;      // 56
    u64 con_out;                 // 64
    u64 standard_error_handle;   // 72
    u64 std_err;                 // 80
    u64 runtime_services;        // 88
    u64 boot_services;           // 96
    u64 number_of_table_entries; // 104
    u64 configuration_table;     // 112
};
static_assert(sizeof(EfiSystemTable) == 120, "EFI_SYSTEM_TABLE head layout");

// UEFI global-variable GUID: 8BE4DF61-93CA-11D2-AA0D-00E098032B8C.
constexpr EfiGuid kGlobalVariableGuid = {
    0x8BE4DF61u, 0x93CAu, 0x11D2u, {0xAAu, 0x0Du, 0x00u, 0xE0u, 0x98u, 0x03u, 0x2Bu, 0x8Cu}};

// UTF-16 "BootOrder".
constexpr u16 kBootOrderName[] = {'B', 'o', 'o', 't', 'O', 'r', 'd', 'e', 'r', 0};

// RuntimeServices->GetVariable byte offset 72 = index 9 of u64 pointers:
// Hdr(24) + GetTime/SetTime/GetWakeupTime/SetWakeupTime(32) +
// SetVirtualAddressMap/ConvertPointer(16) = 72.
constexpr u64 kRtGetVariableIndex = 9;
constexpr u64 kIdentityMapLimit = 0x40000000ULL; // low 1 GiB identity map (RWX)

} // namespace

u64 FindEfiSystemTablePhys(const void* mb_info, u64 size)
{
    if (mb_info == nullptr || size < 8)
        return 0;
    const u8* base = static_cast<const u8*>(mb_info);
    u32 total = *reinterpret_cast<const u32*>(base); // total_size
    if (total > size)
        total = static_cast<u32>(size);

    u64 off = 8; // skip { total_size, reserved }
    while (off + 8 <= total)
    {
        const u32 type = *reinterpret_cast<const u32*>(base + off);
        const u32 tag_size = *reinterpret_cast<const u32*>(base + off + 4);
        if (type == mm::kMultibootTagEnd)
            break;
        if (tag_size < 8)
            break;
        if (type == kMultibootTagEfi64SystemTable && tag_size >= 16 && off + 16 <= total)
            return *reinterpret_cast<const u64*>(base + off + 8);
        off += (static_cast<u64>(tag_size) + 7) & ~7ULL;
    }
    return 0;
}

UefiNvramReading UefiNvramRead()
{
    UefiNvramReading r = {};
    const void* mb = mm::MultibootInfoSnapshot();
    const u64 mb_size = mm::MultibootInfoSnapshotSize();
    const u64 phys = FindEfiSystemTablePhys(mb, mb_size);
    if (phys == 0)
        return r; // bootloader passed no EFI table (legacy BIOS, or GRUB didn't relay)

    r.tag_present = true;
    r.system_table_phys = phys;

    void* virt = mm::MapMmio(phys, sizeof(EfiSystemTable));
    if (virt == nullptr)
        return r; // tag present but the table page couldn't be mapped
    const auto* st = static_cast<const volatile EfiSystemTable*>(virt);
    if (st->hdr.signature != kEfiSystemTableSignature)
        return r; // tag points somewhere that isn't a system table

    r.table_present = true;
    r.efi_revision = st->hdr.revision;
    r.firmware_revision = st->firmware_revision;
    r.runtime_services_present = (st->runtime_services != 0);
    return r;
}

// Hand-written SysV->MS-x64 thunk that issues a RAW indirect call,
// bypassing the kernel's retpoline guard (which panics on a call target
// outside kernel text — and a firmware address is exactly that). See
// arch/x86_64/uefi_call.S.
extern "C" u64 EfiCallGetVariable(void* fn, const u16* name, const EfiGuid* guid, u32* attrs, u64* data_size,
                                  void* data);

const EfiGuid& UefiGlobalVariableGuid()
{
    return kGlobalVariableGuid;
}

UefiVariableResult UefiGetVariable(const u16* name, const EfiGuid* guid)
{
    UefiVariableResult r = {};
    const void* mb = mm::MultibootInfoSnapshot();
    const u64 st_phys = FindEfiSystemTablePhys(mb, mm::MultibootInfoSnapshotSize());
    // The System Table, the Runtime Services table, and the firmware code
    // must all sit in the low 1 GiB identity map (RWX, phys==virt) for a
    // physical-mode call after ExitBootServices. OVMF places them there;
    // if anything is above 1 GiB we cannot safely call and return inert.
    if (st_phys == 0 || st_phys >= kIdentityMapLimit)
        return r;
    void* st_virt = mm::MapMmio(st_phys, sizeof(EfiSystemTable));
    if (st_virt == nullptr)
        return r;
    const auto* st = static_cast<const volatile EfiSystemTable*>(st_virt);
    if (st->hdr.signature != kEfiSystemTableSignature)
        return r;
    const u64 rt_phys = st->runtime_services;
    if (rt_phys == 0 || rt_phys >= kIdentityMapLimit)
        return r;

    const u64* rt = reinterpret_cast<const u64*>(rt_phys);
    void* get_var = reinterpret_cast<void*>(rt[kRtGetVariableIndex]);
    if (get_var == nullptr || reinterpret_cast<u64>(get_var) >= kIdentityMapLimit)
        return r;

    u64 data_size = sizeof(r.data);
    // Save RFLAGS, mask interrupts across the firmware call (RT services
    // don't expect kernel-IRQ re-entry in physical mode), then restore the
    // caller's interrupt state exactly.
    u64 saved_flags = 0;
    asm volatile("pushfq; pop %0; cli" : "=r"(saved_flags) : : "memory");
    const u64 status = EfiCallGetVariable(get_var, name, guid, nullptr, &data_size, r.data);
    asm volatile("push %0; popfq" : : "r"(saved_flags) : "memory", "cc");

    r.efi_status = status;
    if (status == 0)
    {
        r.ok = true;
        r.size = (data_size <= sizeof(r.data)) ? data_size : sizeof(r.data);
    }
    return r;
}

void UefiNvramProbe(bool read_variables)
{
    using arch::SerialWrite;
    const UefiNvramReading r = UefiNvramRead();
    if (!r.tag_present)
    {
        SerialWrite("[uefi] no EFI system table tag (legacy BIOS boot or bootloader didn't relay)");
        // Diagnostic: dump the tag types the bootloader DID pass, so a
        // missing EFI relay is distinguishable from a walker bug.
        const u8* base = static_cast<const u8*>(mm::MultibootInfoSnapshot());
        const u64 sz = mm::MultibootInfoSnapshotSize();
        if (base != nullptr && sz >= 8)
        {
            u32 total = *reinterpret_cast<const u32*>(base);
            if (total > sz)
                total = static_cast<u32>(sz);
            SerialWrite(" tags=[");
            u64 off = 8;
            while (off + 8 <= total)
            {
                const u32 type = *reinterpret_cast<const u32*>(base + off);
                const u32 ts = *reinterpret_cast<const u32*>(base + off + 4);
                if (type == mm::kMultibootTagEnd || ts < 8)
                    break;
                arch::SerialWriteHex(type);
                SerialWrite(" ");
                off += (static_cast<u64>(ts) + 7) & ~7ULL;
            }
            SerialWrite("]");
        }
        SerialWrite("\n");
        return;
    }
    if (!r.table_present)
    {
        SerialWrite("[uefi] EFI system table tag present but unreadable/sig-mismatch phys=");
        arch::SerialWriteHex(r.system_table_phys);
        SerialWrite("\n");
        return;
    }
    SerialWrite("[uefi] system table phys=");
    arch::SerialWriteHex(r.system_table_phys);
    SerialWrite(" efi_rev=");
    arch::SerialWriteHex(r.efi_revision);
    SerialWrite(" fw_rev=");
    arch::SerialWriteHex(r.firmware_revision);
    SerialWrite(r.runtime_services_present ? " runtime-services=present" : " runtime-services=absent");
    if (!read_variables)
    {
        // The firmware GetVariable call is opt-in (cmdline `uefi-getvar`):
        // it calls firmware code in physical mode, so a default boot does
        // not risk it.
        SerialWrite(" getvar=available(pass uefi-getvar)\n");
        return;
    }
    if (!r.runtime_services_present)
    {
        SerialWrite(" getvar=skip(no-rt-services)\n");
        return;
    }
    // Diagnostic before the firmware call so a fault/hang is localised.
    SerialWrite("\n[uefi] calling GetVariable(BootOrder)...\n");
    const UefiVariableResult bo = UefiGetVariable(kBootOrderName, &kGlobalVariableGuid);
    if (bo.ok)
    {
        SerialWrite("[uefi] BootOrder OK: ");
        arch::SerialWriteHex(bo.size);
        SerialWrite(" bytes (");
        arch::SerialWriteHex(bo.size / 2);
        SerialWrite(" boot entries):");
        for (u64 i = 0; i + 1 < bo.size; i += 2)
        {
            const u16 idx = static_cast<u16>(bo.data[i] | (static_cast<u16>(bo.data[i + 1]) << 8));
            SerialWrite(" Boot");
            arch::SerialWriteHex(idx);
        }
        SerialWrite("\n");
    }
    else
    {
        SerialWrite("[uefi] GetVariable(BootOrder) failed status=");
        arch::SerialWriteHex(bo.efi_status);
        SerialWrite("\n");
    }
}

void UefiNvramSelfTest()
{
    using core::PanicWithValue;

    // Signature constant must be the ASCII "IBI SYST" little-endian.
    if (kEfiSystemTableSignature != 0x5453595320494249ULL)
        PanicWithValue("arch/uefi", "EFI sig constant wrong", kEfiSystemTableSignature);

    // Synthetic Multiboot2 blob: header + a tag-12 carrying a known
    // pointer + an end tag. The walker must extract the pointer.
    alignas(8) u8 blob[40] = {};
    *reinterpret_cast<u32*>(blob + 0) = sizeof(blob); // total_size
    *reinterpret_cast<u32*>(blob + 4) = 0;            // reserved
    *reinterpret_cast<u32*>(blob + 8) = kMultibootTagEfi64SystemTable;
    *reinterpret_cast<u32*>(blob + 12) = 16; // tag size
    *reinterpret_cast<u64*>(blob + 16) = 0x00000000CAFEF00DULL;
    *reinterpret_cast<u32*>(blob + 24) = mm::kMultibootTagEnd;
    *reinterpret_cast<u32*>(blob + 28) = 8;
    if (FindEfiSystemTablePhys(blob, sizeof(blob)) != 0x00000000CAFEF00DULL)
        PanicWithValue("arch/uefi", "tag-12 walker miss", 1);

    // A blob with no tag-12 (just the end tag) must return 0.
    alignas(8) u8 empty[16] = {};
    *reinterpret_cast<u32*>(empty + 0) = sizeof(empty);
    *reinterpret_cast<u32*>(empty + 8) = mm::kMultibootTagEnd;
    *reinterpret_cast<u32*>(empty + 12) = 8;
    if (FindEfiSystemTablePhys(empty, sizeof(empty)) != 0)
        PanicWithValue("arch/uefi", "empty blob returned non-zero", 2);

    // Null / undersized inputs are safe.
    if (FindEfiSystemTablePhys(nullptr, 0) != 0 || FindEfiSystemTablePhys(blob, 4) != 0)
        PanicWithValue("arch/uefi", "degenerate input not zero", 3);

    // The global-variable GUID constant (8BE4DF61-93CA-11D2-AA0D-...8C).
    const EfiGuid& g = kGlobalVariableGuid;
    if (g.data1 != 0x8BE4DF61u || g.data2 != 0x93CAu || g.data3 != 0x11D2u || g.data4[0] != 0xAAu ||
        g.data4[7] != 0x8Cu)
        PanicWithValue("arch/uefi", "global-variable GUID constant wrong", g.data1);

    arch::SerialWrite("[uefi-nvram-selftest] PASS (tag-12 walker + signature + GUID constant)\n");
}

} // namespace duetos::arch
