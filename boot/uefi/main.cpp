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
#include "elf_types.h"

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
                         u"  See wiki/kernel/UEFI-Loader.md for the Phase B plan.\r\n";

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

void Com1WriteHex(UINT64 value)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
    {
        const UINT8 nibble = static_cast<UINT8>((value >> ((15 - i) * 4)) & 0xF);
        buf[2 + i] = (nibble < 10) ? static_cast<char>('0' + nibble) : static_cast<char>('A' + nibble - 10);
    }
    buf[18] = '\0';
    Com1Write(buf);
}

// ---------------------------------------------------------------
// Phase B.1 — locate, open, and validate the kernel ELF on the
// boot device. Doesn't yet load segments; that's Phase B.2.
//
// The walk:
//   image_handle  -HandleProtocol(LoadedImage)->  loaded_image
//   loaded_image.DeviceHandle
//                 -HandleProtocol(SimpleFileSystem)->  fs
//   fs.OpenVolume()  ->  root file
//   root.Open(L"\\duetos-kernel.elf", READ)  ->  kernel file
//   kernel.Read(64 bytes)  ->  Elf64_Ehdr
//
// On every step, log success/failure to COM1 with the EFI_STATUS
// so a smoke-test failure pinpoints which step broke. The test
// harness greps for the success marker; failure markers are
// human-diagnostic only.
// ---------------------------------------------------------------

// Path to the kernel image on the ESP. The `\\` prefix anchors at
// the volume root; OVMF expects backslashes (UEFI spec, §13.6).
constexpr CHAR16 kKernelPath[] = u"\\duetos-kernel.elf";

bool ProbeKernelElf(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE* st)
{
    EFI_BOOT_SERVICES* bs = st->BootServices;
    if (bs == nullptr)
    {
        Com1Write("[uefi-b1] no BootServices\r\n");
        return false;
    }

    // Step 1: locate this loader's LoadedImage. The DeviceHandle
    // there is the volume we were loaded from — the ESP under
    // QEMU+OVMF, the user's EFI partition on real hardware.
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = nullptr;
    EFI_GUID li_guid = kEfiLoadedImageProtocolGuid;
    EFI_STATUS s = bs->HandleProtocol(image_handle, &li_guid, reinterpret_cast<void**>(&loaded_image));
    if (s != EFI_SUCCESS || loaded_image == nullptr)
    {
        Com1Write("[uefi-b1] HandleProtocol(LoadedImage) FAIL status=");
        Com1WriteHex(s);
        Com1Write("\r\n");
        return false;
    }

    // Step 2: walk to the volume's SimpleFileSystem.
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = nullptr;
    EFI_GUID fs_guid = kEfiSimpleFileSystemProtocolGuid;
    s = bs->HandleProtocol(loaded_image->DeviceHandle, &fs_guid, reinterpret_cast<void**>(&fs));
    if (s != EFI_SUCCESS || fs == nullptr)
    {
        Com1Write("[uefi-b1] HandleProtocol(SimpleFileSystem) FAIL status=");
        Com1WriteHex(s);
        Com1Write("\r\n");
        return false;
    }

    // Step 3: open the volume root.
    EFI_FILE_PROTOCOL* root = nullptr;
    s = fs->OpenVolume(fs, &root);
    if (s != EFI_SUCCESS || root == nullptr)
    {
        Com1Write("[uefi-b1] OpenVolume FAIL status=");
        Com1WriteHex(s);
        Com1Write("\r\n");
        return false;
    }

    // Step 4: open the kernel ELF read-only.
    EFI_FILE_PROTOCOL* kernel_file = nullptr;
    s = root->Open(root, &kernel_file, const_cast<CHAR16*>(kKernelPath), kEfiFileModeRead, 0);
    (void)root->Close(root); // root no longer needed
    if (s != EFI_SUCCESS || kernel_file == nullptr)
    {
        Com1Write("[uefi-b1] Open(duetos-kernel.elf) FAIL status=");
        Com1WriteHex(s);
        Com1Write("\r\n");
        return false;
    }

    // Step 5: read the 64-byte ELF header into a stack buffer.
    elf::Elf64_Ehdr ehdr{};
    UINTN read_size = sizeof(ehdr);
    s = kernel_file->Read(kernel_file, &read_size, &ehdr);
    (void)kernel_file->Close(kernel_file);
    if (s != EFI_SUCCESS || read_size != sizeof(ehdr))
    {
        Com1Write("[uefi-b1] Read(Elf64_Ehdr) FAIL status=");
        Com1WriteHex(s);
        Com1Write(" got=");
        Com1WriteHex(read_size);
        Com1Write("\r\n");
        return false;
    }

    // Step 6: validate ELF magic + class + endianness + machine.
    // Reject anything that isn't a 64-bit little-endian x86_64
    // executable — those four checks together rule out: PE
    // binaries, ELF32, big-endian builds, ARM/RISC-V/other-arch
    // ELF, ET_REL/ET_DYN that need link-time fixup. ET_EXEC is
    // also accepted; ET_DYN with a kernel-ish e_entry could be
    // accepted later but Phase B.2 will probably gate on ET_EXEC
    // until PIE kernels become a real workload.
    if (ehdr.e_ident[elf::EI_MAG0] != elf::ELFMAG0 || ehdr.e_ident[elf::EI_MAG1] != elf::ELFMAG1 ||
        ehdr.e_ident[elf::EI_MAG2] != elf::ELFMAG2 || ehdr.e_ident[elf::EI_MAG3] != elf::ELFMAG3)
    {
        Com1Write("[uefi-b1] ELF magic mismatch\r\n");
        return false;
    }
    if (ehdr.e_ident[elf::EI_CLASS] != elf::ELFCLASS64)
    {
        Com1Write("[uefi-b1] not ELFCLASS64\r\n");
        return false;
    }
    if (ehdr.e_ident[elf::EI_DATA] != elf::ELFDATA2LSB)
    {
        Com1Write("[uefi-b1] not little-endian\r\n");
        return false;
    }
    if (ehdr.e_machine != elf::EM_X86_64)
    {
        Com1Write("[uefi-b1] e_machine != EM_X86_64; got=");
        Com1WriteHex(ehdr.e_machine);
        Com1Write("\r\n");
        return false;
    }

    Com1Write("[uefi-b1] kernel ELF: valid x86_64 image; e_entry=");
    Com1WriteHex(ehdr.e_entry);
    Com1Write(" e_phnum=");
    Com1WriteHex(ehdr.e_phnum);
    Com1Write("\r\n");
    return true;
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

extern "C" duetos::boot::uefi::EFI_STATUS efi_main(duetos::boot::uefi::EFI_HANDLE image_handle,
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

    // Phase B.1 — open + validate the kernel ELF header. Result
    // logged to COM1; the smoke test greps for the success
    // marker. Failure here is non-fatal at this slice (we still
    // halt below); Phase B.2 will replace the halt with a full
    // load + jump and a failure here will become a hard error.
    (void)ProbeKernelElf(image_handle, system_table);

    // Pace for a moment so the banner is observable on hardware
    // that auto-advances past loaders. 2 seconds is invisible to
    // a human and trivial in QEMU.
    if (system_table->BootServices != nullptr && system_table->BootServices->Stall != nullptr)
    {
        (void)system_table->BootServices->Stall(2 * 1000 * 1000); // 2 s
    }

    Halt();
}
