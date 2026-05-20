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
//   Slice 2: IOAPIC MMIO + PIT + COM1 RX/IRQ4 + HLT resume.
//   Slice 3: host-side GDB remote (--gdb <port>) for VS attach.
//   Slice 4: ELF-symbol introspection + vmexit ring via `monitor`.
//   Slice 5 (this commit): record/replay of host-origin inputs
//   (--record <f> / --replay <f>) keyed by exit-seq — serial RX,
//   IOAPIC line raises, PIT-ch2 calibration edge. Reproduces the
//   exit stream at exit-seq granularity (NOT cycle-exact: WHP owns
//   the LAPIC timer internally). Framebuffer / virtio-blk are
//   intentionally NOT built — the kernel boots headless with a
//   baked ramfs, so they are unneeded for the run/test/debug goal
//   and would be unwired bloat; revisit only if a GUI/disk
//   workload actually needs them.
// ===========================================================================
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

#include <windows.h>

#include "vmm.h"
#include "whp.h"

namespace
{

void Usage(const char* argv0)
{
    std::fprintf(stderr,
                 "usage: %s --kernel <elf> [--mem <MiB>] "
                 "[--cmdline \"...\"] [--idle <secs>] "
                 "[--gdb <port>] [--record <f> | --replay <f>] "
                 "[--res WxH] [--no-window]\n",
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
        else if (a == "--gdb")
        {
            cfg.gdbPort = static_cast<uint16_t>(
                std::strtoul(next("--gdb"), nullptr, 10));
        }
        else if (a == "--record")
        {
            cfg.recordPath = next("--record");
        }
        else if (a == "--replay")
        {
            cfg.replayPath = next("--replay");
        }
        else if (a == "--res")
        {
            const char* v = next("--res");
            if (std::sscanf(v, "%ux%u", &cfg.fbW, &cfg.fbH) != 2 ||
                cfg.fbW == 0 || cfg.fbH == 0)
            {
                std::fprintf(stderr,
                             "--res requires WxH (e.g. 1280x1024)\n");
                return 2;
            }
        }
        else if (a == "--no-window")
        {
            cfg.noWindow = true;
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

    // If no explicit --res was given and we are not headless, query the
    // primary monitor. Fall back to 1280x1024 if the API returns 0
    // (e.g. running in a service/session-0 context with no display).
    if (!cfg.noWindow && cfg.fbW == 0)
    {
        cfg.fbW = static_cast<uint32_t>(GetSystemMetrics(SM_CXSCREEN));
        cfg.fbH = static_cast<uint32_t>(GetSystemMetrics(SM_CYSCREEN));
        if (cfg.fbW == 0 || cfg.fbH == 0)
        {
            cfg.fbW = 1280;
            cfg.fbH = 1024;
        }
    }
    if (!cfg.recordPath.empty() && !cfg.replayPath.empty())
    {
        std::fprintf(stderr,
                     "--record and --replay are mutually exclusive\n");
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
