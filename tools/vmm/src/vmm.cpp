#include "vmm.h"

#include <algorithm>
#include <cstdio>

#include "acpi.h"
#include "elf64.h"
#include "multiboot2.h"

namespace duetos::vmm
{

namespace
{
uint64_t Align2M(uint64_t x) { return (x + 0x1FFFFF) & ~uint64_t(0x1FFFFF); }
} // namespace

Vmm::Vmm(VmConfig cfg) : m_cfg(std::move(cfg)), m_part(/*cpuCount=*/1)
{
    m_mem = std::make_unique<GuestMemory>(m_part, m_cfg.ramBytes);

    LoadedImage img = LoadElf64(m_cfg.kernelPath, *m_mem);
    std::printf("[vmm] kernel: entry=0x%llx load=[0x%llx,0x%llx)\n",
                (unsigned long long)img.entry,
                (unsigned long long)img.lowPaddr,
                (unsigned long long)img.highPaddr);

    AcpiImage acpi = BuildAcpi(kAcpiGpa, /*lapicCount=*/1);
    m_mem->Write(acpi.baseGpa, acpi.blob.data(), acpi.blob.size());

    const uint64_t reservedEnd =
        Align2M(std::max<uint64_t>(
            {img.highPaddr, kAcpiGpa + acpi.blob.size(),
             kMbInfoGpa + 0x10000}));

    Mb2Params mp;
    mp.cmdline     = m_cfg.cmdline;
    mp.ramBytes    = m_cfg.ramBytes;
    mp.reservedEnd = reservedEnd;
    mp.rsdp        = acpi.rsdp;
    std::vector<uint8_t> mbi = BuildMultiboot2Info(mp);
    m_mem->Write(kMbInfoGpa, mbi.data(), mbi.size());

    SetupVcpu(img.entry, kMbInfoGpa);
}

void Vmm::SetupVcpu(uint64_t entry, uint64_t mbInfoGpa)
{
    // Multiboot2 machine state: 32-bit protected mode, paging OFF,
    // flat 4 GiB segments, EAX=magic, EBX=&mbi. boot.S takes it from
    // here (its own GDT, long-mode bringup, higher-half map).
    WHV_REGISTER_NAME n[16];
    WHV_REGISTER_VALUE v[16];
    int i = 0;

    auto reg = [&](WHV_REGISTER_NAME name, uint64_t val) {
        n[i] = name;
        v[i] = {};
        v[i].Reg64 = val;
        ++i;
    };
    auto seg = [&](WHV_REGISTER_NAME name, uint16_t sel, bool code) {
        n[i] = name;
        v[i] = {};
        WHV_X64_SEGMENT_REGISTER s = {};
        s.Base = 0;
        s.Limit = 0xFFFFFFFF;
        s.Selector = sel;
        s.SegmentType = code ? 0xB : 0x3; // exec/read vs read/write
        s.NonSystemSegment = 1;
        s.Present = 1;
        s.Default = 1;     // 32-bit
        s.Granularity = 1; // 4 KiB → limit is in pages
        v[i].Segment = s;
        ++i;
    };

    reg(WHvX64RegisterCr0, 0x00000011);  // PE | ET, PG=0
    reg(WHvX64RegisterCr3, 0);
    reg(WHvX64RegisterCr4, 0);
    reg(WHvX64RegisterEfer, 0);
    reg(WHvX64RegisterRflags, 0x2);      // reserved bit, IF=0
    reg(WHvX64RegisterRip, entry);
    reg(WHvX64RegisterRsp, 0x7000);      // boot.S installs its own
    reg(WHvX64RegisterRax, kMultiboot2BootloaderMagic);
    reg(WHvX64RegisterRbx, mbInfoGpa);
    seg(WHvX64RegisterCs, 0x08, true);
    seg(WHvX64RegisterDs, 0x10, false);
    seg(WHvX64RegisterEs, 0x10, false);
    seg(WHvX64RegisterFs, 0x10, false);
    seg(WHvX64RegisterGs, 0x10, false);
    seg(WHvX64RegisterSs, 0x10, false);

    m_part.SetRegisters(0, n, i, v);
}

bool Vmm::HandleIoPort(const WHV_RUN_VP_EXIT_CONTEXT& exit)
{
    const auto& io = exit.IoPortAccess;
    const uint16_t port = static_cast<uint16_t>(io.PortNumber);
    const bool claimed = m_com1.Handles(port);

    // Unclaimed ports behave like a bus with no decoder: reads see
    // all-ones, writes are dropped.
    uint64_t rax = io.Rax;
    if (io.AccessInfo.IsWrite)
    {
        if (claimed)
        {
            m_com1.Out(port, static_cast<uint32_t>(rax));
        }
    }
    else
    {
        uint32_t val = claimed ? m_com1.In(port) : 0xFFFFFFFFu;
        const uint32_t bytes = io.AccessInfo.AccessSize;
        uint64_t mask = (bytes >= 4) ? 0xFFFFFFFFull
                                     : ((1ull << (bytes * 8)) - 1);
        rax = (rax & ~mask) | (val & mask);
    }

    // Retire the IN/OUT: write back RAX and step RIP past it.
    WHV_REGISTER_NAME n[2] = {WHvX64RegisterRax, WHvX64RegisterRip};
    WHV_REGISTER_VALUE vv[2] = {};
    vv[0].Reg64 = rax;
    vv[1].Reg64 = exit.VpContext.Rip + exit.VpContext.InstructionLength;
    m_part.SetRegisters(0, n, 2, vv);
    return true;
}

int Vmm::Run()
{
    std::printf("[vmm] booting DuetOS guest (1 vCPU, %llu MiB)\n",
                (unsigned long long)(m_cfg.ramBytes >> 20));
    std::fflush(stdout);

    for (;;)
    {
        WHV_RUN_VP_EXIT_CONTEXT exit = m_part.Run(0);
        switch (exit.ExitReason)
        {
        case WHvRunVpExitReasonX64IoPortAccess:
            if (exit.IoPortAccess.AccessInfo.StringOp)
            {
                std::printf("\n[vmm] string I/O at port 0x%x "
                            "(unimplemented in v0)\n",
                            exit.IoPortAccess.PortNumber);
                return 2;
            }
            HandleIoPort(exit);
            break;

        case WHvRunVpExitReasonX64Halt:
            // No timer/IRQ source until slice 2, so a HLT here means
            // the kernel reached an idle/wait with nothing to wake
            // it. For slice 1 that IS the success terminus: the
            // serial banner has already streamed to stdout above.
            std::printf("\n[vmm] guest HLT — slice-1 terminus "
                        "(timer/IRQ lands in slice 2)\n");
            return 0;

        case WHvRunVpExitReasonMemoryAccess:
            std::printf("\n[vmm] unhandled MMIO @ 0x%llx — slice-1 "
                        "boundary (IOAPIC/fb land in slice 2)\n",
                        (unsigned long long)
                            exit.MemoryAccess.Gpa);
            return 0;

        case WHvRunVpExitReasonX64InterruptWindow:
            break; // nothing to inject yet (slice 2)

        case WHvRunVpExitReasonCanceled:
            std::printf("\n[vmm] run canceled\n");
            return 1;

        default:
            std::printf("\n[vmm] unexpected exit reason %d "
                        "(rip=0x%llx)\n",
                        (int)exit.ExitReason,
                        (unsigned long long)exit.VpContext.Rip);
            return 1;
        }
    }
}

} // namespace duetos::vmm
