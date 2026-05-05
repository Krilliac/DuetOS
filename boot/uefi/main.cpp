/*
 * DuetOS — UEFI boot loader, Phase A.
 *
 * Phase A scope (this commit):
 *   - Produce a valid PE32+ EFI Application that the firmware
 *     accepts as `EFI/BOOT/BOOTX64.EFI` on a FAT32 ESP.
 *   - Print a banner via `SystemTable->ConOut->OutputString` so
 *     a human at the console (or `tools/qemu/run.sh -bios OVMF`)
 *     can confirm the loader's entry point fired and the toolchain
 *     produced a working binary.
 *   - Halt deterministically (no kernel handoff yet).
 *
 * Phase B scope (next slice):
 *   - Locate the kernel ELF on the boot device via Simple File
 *     System / File protocol.
 *   - Allocate pages and load each ELF segment.
 *   - Get the UEFI memory map (GetMemoryMap), the framebuffer
 *     descriptor (Graphics Output Protocol).
 *   - Synthesise a Multiboot2 info structure so the existing
 *     kernel/arch/x86_64/boot.S entry continues to work.
 *   - ExitBootServices, jump to the kernel's _start equivalent.
 *
 * Build target: PE32+ with Subsystem=10 (EFI Application). The
 * MS x64 calling convention is the default for `-target
 * x86_64-unknown-windows`; no per-function attribute needed.
 *
 * Linkage: this TU is the entire loader image — no separate
 * runtime, no libc. We do not call any helper that would
 * require the EDK2/gnu-efi library (memcpy, AsciiPrint, …).
 * Anything we need lives directly in this file.
 */

#include "efi_types.h"

namespace duetos::boot::uefi
{

// ---------------------------------------------------------------
// Phase A banner. UEFI strings are CHAR16 (UCS-2) and require
// CRLF line endings on most firmware. The banner is short on
// purpose — every byte we add to a Phase A loader is dead weight
// once the real loader replaces it.
// ---------------------------------------------------------------

const CHAR16 kBanner[] = u"DuetOS UEFI loader v0 (Phase A: toolchain proof)\r\n"
                         u"  This loader does not yet load the kernel.\r\n"
                         u"  See wiki/boot/UEFI-Loader.md for the Phase B plan.\r\n";

// ---------------------------------------------------------------
// Halt the CPU forever. UEFI applications can return from
// `efi_main` to give control back to the firmware (which would
// then drop the user at the boot menu); we instead `cli; hlt;`
// in a loop so the message stays on screen until the user
// reboots — useful while iterating on the toolchain.
// ---------------------------------------------------------------

[[noreturn]] void Halt()
{
    for (;;)
    {
        __asm__ volatile("cli; hlt");
    }
}

} // namespace duetos::boot::uefi

// ---------------------------------------------------------------
// `efi_main` — the firmware's entry point. Lives in the global
// namespace because the linker's `-entry:efi_main` looks up the
// undecorated name. Microsoft x64 ABI: `image_handle` arrives
// in RCX, `system_table` in RDX. With `-target
// x86_64-unknown-windows` clang emits the Windows prolog/epilog
// automatically, so a plain function signature is correct.
// ---------------------------------------------------------------

extern "C" duetos::boot::uefi::EFI_STATUS efi_main(duetos::boot::uefi::EFI_HANDLE /*image_handle*/,
                                                   duetos::boot::uefi::EFI_SYSTEM_TABLE* system_table)
{
    using namespace duetos::boot::uefi;

    if (system_table == nullptr || system_table->ConOut == nullptr)
    {
        // No console — nothing observable from this binary at all.
        // A real Phase B loader would still attempt the load,
        // since headless boots are valid; Phase A is purely about
        // proving a human-visible signal made it out.
        Halt();
    }

    // Reset the console first. Some firmwares (notably OVMF) leave
    // ConOut in a state where the first OutputString is dropped
    // unless Reset has run; the cost is one extra firmware call.
    (void)system_table->ConOut->Reset(system_table->ConOut, /*extended=*/0);

    // Cast away const for the firmware's mutable-pointer parameter.
    // OutputString does not modify the buffer — the spec just
    // omits the const qualifier.
    (void)system_table->ConOut->OutputString(system_table->ConOut, const_cast<CHAR16*>(kBanner));

    // Pace for a moment so the banner is observable on hardware
    // that auto-advances past loaders. 2 seconds is invisible to
    // a human and trivial in QEMU.
    if (system_table->BootServices != nullptr && system_table->BootServices->Stall != nullptr)
    {
        (void)system_table->BootServices->Stall(2 * 1000 * 1000); // 2 s
    }

    Halt();
}
