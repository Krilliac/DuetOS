// ===========================================================================
// duetos-vmm — bespoke Windows Hypervisor Platform VMM for DuetOS.
//
// WHAT
//   Boots the *unmodified* freestanding DuetOS kernel ELF as a
//   hardware-virtualised guest on Windows via WHP. Emulates only the
//   firmware/devices DuetOS actually probes (Multiboot2 handoff,
//   synthesised ACPI, 16550 COM1). No QEMU, no GRUB, no UEFI.
//
// WHY
//   QEMU+gdb can boot the kernel but can't introspect its internals.
//   Owning the hypervisor lets later slices walk guest structures
//   host-side, single-step deterministically, and expose a GDB-remote
//   that Visual Studio attaches to — all in a native MSVC .exe.
//
// USAGE
//   duetos-vmm.exe --kernel <duetos-kernel.elf>
//                  [--mem <MiB>] [--cmdline "<kernel cmdline>"]
//   Defaults: --mem 512, --cmdline "console=ttyS0".
//   Guest COM1 output streams to this process's stdout.
//
// BUILD
//   Windows only (links WinHvPlatform.lib; needs the "Windows
//   Hypervisor Platform" optional feature). See tools/vmm/CMakeLists.txt.
//
// SLICE STATUS
//   Slice 1: partition + vCPU + ELF + MB2/ACPI + COM1.
//   Slice 2 (this commit): IOAPIC MMIO + PIT (LAPIC-timer
//   calibration reference + ch0 fallback) + COM1 RX/IRQ4 + HLT
//   resume + idle watchdog → scheduler runs, interactive shell over
//   stdin/stdout. Slices 3-5 (GDB-remote, DWARF introspection,
//   record/replay) follow.
// ===========================================================================
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

#include "vmm.h"
#include "whp.h"

namespace
{

void Usage(const char* argv0)
{
    std::fprintf(stderr,
                 "usage: %s --kernel <elf> [--mem <MiB>] "
                 "[--cmdline \"...\"] [--idle <secs>]\n",
                 argv0);
}

} // namespace

int main(int argc, char** argv)
{
    duetos::vmm::VmConfig cfg;

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        auto next = [&](const char* name) -> const char* {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "%s requires an argument\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--kernel")
        {
            cfg.kernelPath = next("--kernel");
        }
        else if (a == "--mem")
        {
            cfg.ramBytes =
                std::strtoull(next("--mem"), nullptr, 10) * 1024 * 1024;
        }
        else if (a == "--cmdline")
        {
            cfg.cmdline = next("--cmdline");
        }
        else if (a == "--idle")
        {
            cfg.idleSecs = static_cast<uint32_t>(
                std::strtoul(next("--idle"), nullptr, 10));
        }
        else if (a == "-h" || a == "--help")
        {
            Usage(argv[0]);
            return 0;
        }
        else
        {
            std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
            Usage(argv[0]);
            return 2;
        }
    }

    if (cfg.kernelPath.empty())
    {
        Usage(argv[0]);
        return 2;
    }

    if (!duetos::vmm::HypervisorPresent())
    {
        std::fprintf(stderr,
                     "[vmm] Windows hypervisor not present. Enable the "
                     "\"Windows Hypervisor Platform\" Windows feature "
                     "and ensure virtualization is on in firmware.\n");
        return 1;
    }

    try
    {
        duetos::vmm::Vmm vm(std::move(cfg));
        return vm.Run();
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[vmm] fatal: %s\n", e.what());
        return 1;
    }
}
