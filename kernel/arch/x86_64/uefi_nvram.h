#pragma once

#include "util/types.h"

/*
 * DuetOS — UEFI firmware / NVRAM reader, v0.
 *
 * READ-ONLY. Captures the EFI System Table the bootloader passed via the
 * Multiboot2 EFI64-system-table tag (type 12), maps it, and reports the
 * firmware identity from its header. It writes NOTHING — UEFI variable
 * WRITES (SetVariable) can brick a board (wiki/security/Hardware-Safety.md),
 * so even when the full reader lands it stays read-only / append-only.
 *
 * What v0 reports (when the bootloader provided tag 12):
 *   - the EFI System Table physical address + a verified signature,
 *   - the EFI spec revision + firmware revision from the table header,
 *   - whether the Runtime Services table pointer is present (the handle
 *     a future GetVariable would call through).
 *
 * GAP (v0, deliberate): the actual `GetVariable` (read Boot####,
 * BootOrder, enumerate variables) is NOT implemented. It needs the
 * Multiboot2 EFI memory-map tag (type 17) parsed so the
 * EfiRuntimeServicesCode/Data regions can be mapped, plus an MS-x64-ABI
 * thunk to call RuntimeServices->GetVariable in physical mode. That is a
 * follow-up; v0 puts the System-Table reader in place and pins the gap.
 *
 * Verifiable under QEMU: run.sh boots OVMF (UEFI) by default, so GRUB
 * passes tag 12 and the firmware revision is readable. DUETOS_LEGACY=1
 * (SeaBIOS) has no EFI table → table_present=false.
 *
 * Context: kernel — runs after the Multiboot2 snapshot is captured.
 */

namespace duetos::arch
{

struct UefiNvramReading
{
    bool table_present;            // tag 12 found AND signature verified
    bool tag_present;              // tag 12 was present (even if sig bad)
    u64 system_table_phys;         // physical address of EFI_SYSTEM_TABLE
    u32 efi_revision;              // EFI_TABLE_HEADER.Revision (spec rev)
    u32 firmware_revision;         // vendor firmware revision
    bool runtime_services_present; // RuntimeServices pointer non-null
};

/// Scan a Multiboot2 info blob for the EFI64-system-table tag (type 12)
/// and return the EFI System Table physical address, or 0 if absent.
/// Pure function over the blob — exposed for the self-test.
u64 FindEfiSystemTablePhys(const void* mb_info, u64 size);

/// Read the EFI System Table header captured at boot. Zeroed
/// (table_present=false) when the bootloader passed no tag 12 (e.g.
/// legacy BIOS boot) or the signature does not verify.
UefiNvramReading UefiNvramRead();

/// Sample once + log a one-line summary at boot.
void UefiNvramProbe();

/// Pure-math self-test of the tag-12 walker over a synthetic Multiboot2
/// blob + the signature constant. Panics on mismatch; emits one
/// "[uefi-nvram-selftest] PASS" line.
void UefiNvramSelfTest();

} // namespace duetos::arch
