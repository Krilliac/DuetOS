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

// ---------------------------------------------------------------
// Direct COM1 banner. UEFI's `ConOut` routes to whatever the
// firmware considers the "console" — graphical on most boards,
// captured by OVMF's text mode in QEMU. CI / `tools/test/uefi-
// smoke.sh` greps the QEMU serial log, which is wired to COM1
// (port 0x3F8). Writing the banner directly to COM1 in addition
// to ConOut makes the smoke test robust on any firmware: the
// banner appears in the serial log even when the firmware drops
// ConOut, and on real hardware the COM1 write is a harmless no-
// op if the port isn't connected.
//
// We do not configure the UART — UEFI firmware leaves COM1
// initialised at 115200 8N1 in OVMF, and we accept whatever the
// firmware set up. `outb 0x3F8` blocks until the THR is empty
// (we busy-poll LSR.5) so a slow consumer doesn't drop bytes.
// ---------------------------------------------------------------

inline void OutB(UINT16 port, UINT8 value)
{
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

inline UINT8 InB(UINT16 port)
{
    UINT8 v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

void Com1Write(const char* ascii)
{
    constexpr UINT16 kCom1Base = 0x3F8;
    constexpr UINT16 kCom1Lsr = kCom1Base + 5;
    constexpr UINT8 kLsrThrEmpty = 1u << 5;
    while (*ascii != '\0')
    {
        // Busy-poll until the transmit holding register is
        // empty. Bounded by hardware tx rate; in QEMU it's
        // effectively zero-wait.
        while ((InB(kCom1Lsr) & kLsrThrEmpty) == 0)
        {
            __asm__ volatile("pause");
        }
        OutB(kCom1Base, static_cast<UINT8>(*ascii));
        ++ascii;
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

    // Mirror the banner to COM1 so `tools/test/uefi-smoke.sh`'s
    // serial-log grep finds the marker. ConOut goes to the
    // graphical console under OVMF and is invisible to the test
    // harness; COM1 is what QEMU's `-serial` flag captures.
    Com1Write("DuetOS UEFI loader v0 (Phase A: toolchain proof)\r\n");
    Com1Write("  Loader does not yet load the kernel — see\r\n");
    Com1Write("  wiki/kernel/UEFI-Loader.md for the Phase B plan.\r\n");

    // Pace for a moment so the banner is observable on hardware
    // that auto-advances past loaders. 2 seconds is invisible to
    // a human and trivial in QEMU.
    if (system_table->BootServices != nullptr && system_table->BootServices->Stall != nullptr)
    {
        (void)system_table->BootServices->Stall(2 * 1000 * 1000); // 2 s
    }

    Halt();
}
