#include "arch/x86_64/machine_check.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "mm/poison.h"

namespace duetos::arch
{

namespace
{

// IA32 MCA architectural MSRs (SDM Vol 3, Ch 16).
constexpr u32 kMsrIa32McgCap = 0x179;
constexpr u32 kMsrIa32McgStatus = 0x17A;
// Per-bank block: STATUS/ADDR/MISC at 0x401/0x402/0x403 + 4*i.
constexpr u32 kMsrMcStatus(u32 i)
{
    return 0x401 + 4 * i;
}
constexpr u32 kMsrMcAddr(u32 i)
{
    return 0x402 + 4 * i;
}
constexpr u32 kMsrMcMisc(u32 i)
{
    return 0x403 + 4 * i;
}

// MCG_STATUS bits.
constexpr u64 kMcgStatusRipv = 1ULL << 0; // restart IP valid (resumable)
constexpr u64 kMcgStatusEipv = 1ULL << 1; // error IP valid
constexpr u64 kMcgStatusMcip = 1ULL << 2; // machine-check in progress
constexpr u64 kMcgStatusLmce = 1ULL << 3; // local MCE signalled (LMCE_P only)

// MCG_CAP bits.
constexpr u64 kMcgCapCtlP = 1ULL << 8;
constexpr u64 kMcgCapCmciP = 1ULL << 10;
constexpr u64 kMcgCapSerP = 1ULL << 24;
constexpr u64 kMcgCapLmceP = 1ULL << 27;

// MCi_STATUS bits.
constexpr u64 kMcStatusVal = 1ULL << 63;
constexpr u64 kMcStatusOver = 1ULL << 62;
constexpr u64 kMcStatusUc = 1ULL << 61;
constexpr u64 kMcStatusEn = 1ULL << 60;
constexpr u64 kMcStatusMiscv = 1ULL << 59;
constexpr u64 kMcStatusAddrv = 1ULL << 58;
constexpr u64 kMcStatusPcc = 1ULL << 57;
constexpr u64 kMcStatusS = 1ULL << 56;  // signalling (TES/SER)
constexpr u64 kMcStatusAr = 1ULL << 55; // action required (SER)

// Bound the bank walk. MCG_CAP[7:0] is the architectural count;
// a corrupted MCG_CAP (the very thing a hardware fault can do)
// must not drive an unbounded MSR-read loop.
constexpr u32 kMaxBanks = 64;

// Classify the 16-bit MCA compound error code into a top-level
// hardware class. The raw code is always printed alongside this
// so a finer offline decode (RRRR/TT/LL sub-fields) stays
// possible — we deliberately stop at the class, not the full
// sub-field tree, because the class is what an operator triages
// on (bad DIMM vs. bad cache vs. bad bus).
const char* McaErrorClass(u16 code)
{
    if (code == 0x0000)
        return "no-error";
    if (code == 0x0400)
        return "internal-timer";
    if ((code & 0xFFFC) == 0x0000)
        return "internal/external (unclassified, ucode-parity, external, FRC)";
    if ((code & 0xFFF0) == 0x0010)
        return "TLB error";
    if ((code & 0xFF80) == 0x0080)
        return "memory-controller error";
    if ((code & 0xFF00) == 0x0100)
        return "cache hierarchy error";
    if ((code & 0xF800) == 0x0800)
        return "bus / interconnect error";
    return "model-specific / unknown";
}

void DecodeFlag(u64 status, u64 bit, const char* name)
{
    if ((status & bit) != 0)
    {
        SerialWrite(" ");
        SerialWrite(name);
    }
}

} // namespace

MachineCheckVerdict MachineCheckReport(const TrapFrame* frame)
{
    SerialWrite("\n** MACHINE CHECK (#MC) **\n");
    SerialWrite("  faulting rip : ");
    SerialWriteHex(frame != nullptr ? frame->rip : 0);
    SerialWrite("\n  cs           : ");
    SerialWriteHex(frame != nullptr ? frame->cs : 0);
    SerialWrite(((frame != nullptr) && (frame->cs & 3) == 3) ? " (ring 3)\n" : " (ring 0)\n");

    const u64 mcg_cap = ReadMsr(kMsrIa32McgCap);
    const u64 mcg_status = ReadMsr(kMsrIa32McgStatus);
    u32 banks = u32(mcg_cap & 0xFF);
    if (banks > kMaxBanks)
        banks = kMaxBanks;

    SerialWrite("  MCG_CAP      : ");
    SerialWriteHex(mcg_cap);
    SerialWrite(" banks=");
    SerialWriteHex(banks);
    DecodeFlag(mcg_cap, kMcgCapCtlP, "CTL_P");
    DecodeFlag(mcg_cap, kMcgCapCmciP, "CMCI_P");
    DecodeFlag(mcg_cap, kMcgCapSerP, "SER_P");
    DecodeFlag(mcg_cap, kMcgCapLmceP, "LMCE_P");
    SerialWrite("\n  MCG_STATUS   : ");
    SerialWriteHex(mcg_status);
    DecodeFlag(mcg_status, kMcgStatusRipv, "RIPV");
    DecodeFlag(mcg_status, kMcgStatusEipv, "EIPV");
    DecodeFlag(mcg_status, kMcgStatusMcip, "MCIP");
    if ((mcg_cap & kMcgCapLmceP) != 0)
        DecodeFlag(mcg_status, kMcgStatusLmce, "LMCE_S");
    SerialWrite("\n");

    bool any_val = false;
    bool any_pcc = false;
    bool any_uc = false;
    u32 worst_bank = 0;
    // Track the *first* bank that reports a SRAR-class error
    // (Software Recoverable, Action Required: AR=1 + S=1 + UC=1 +
    // PCC=0, with ADDRV=1 giving a usable physical address). The
    // recorded address feeds `mm::PoisonFrame` in the
    // RestartableInfo verdict arm so the failing frame never
    // re-enters the free pool. Intel SDM Vol 3 §16.4.2.1.
    bool srar_present = false;
    u64 srar_addr = 0;

    for (u32 i = 0; i < banks; ++i)
    {
        const u64 status = ReadMsr(kMsrMcStatus(i));
        if ((status & kMcStatusVal) == 0)
            continue;

        any_val = true;
        const u16 mca_code = u16(status & 0xFFFF);
        const u16 model_code = u16((status >> 16) & 0xFFFF);

        SerialWrite("  bank ");
        SerialWriteHex(i);
        SerialWrite(" MCi_STATUS=");
        SerialWriteHex(status);
        DecodeFlag(status, kMcStatusOver, "OVER");
        DecodeFlag(status, kMcStatusUc, "UC");
        DecodeFlag(status, kMcStatusEn, "EN");
        DecodeFlag(status, kMcStatusMiscv, "MISCV");
        DecodeFlag(status, kMcStatusAddrv, "ADDRV");
        DecodeFlag(status, kMcStatusPcc, "PCC");
        if ((mcg_cap & kMcgCapSerP) != 0)
        {
            DecodeFlag(status, kMcStatusS, "S");
            DecodeFlag(status, kMcStatusAr, "AR");
        }
        SerialWrite("\n    mca-code   : ");
        SerialWriteHex(mca_code);
        SerialWrite(" (");
        SerialWrite(McaErrorClass(mca_code));
        SerialWrite(")\n    model-code : ");
        SerialWriteHex(model_code);
        SerialWrite("\n");

        if ((status & kMcStatusAddrv) != 0)
        {
            SerialWrite("    MCi_ADDR   : ");
            SerialWriteHex(ReadMsr(kMsrMcAddr(i)));
            SerialWrite("\n");
        }
        if ((status & kMcStatusMiscv) != 0)
        {
            SerialWrite("    MCi_MISC   : ");
            SerialWriteHex(ReadMsr(kMsrMcMisc(i)));
            SerialWrite("\n");
        }

        if ((status & kMcStatusPcc) != 0)
        {
            any_pcc = true;
            worst_bank = i;
        }
        if ((status & kMcStatusUc) != 0)
        {
            any_uc = true;
            if (!any_pcc)
                worst_bank = i;
        }
        // SRAR detection (Software Recoverable, Action Required).
        // The exact gate (S=1, AR=1, UC=1, PCC=0, ADDRV=1) is per
        // Intel SDM Vol 3 §16.4.2.1 — "Action Required" class.
        if ((status & kMcStatusS) != 0 && (status & kMcStatusAr) != 0 && (status & kMcStatusUc) != 0 &&
            (status & kMcStatusPcc) == 0 && (status & kMcStatusAddrv) != 0 && !srar_present)
        {
            srar_present = true;
            srar_addr = ReadMsr(kMsrMcAddr(i));
        }
    }

    MachineCheckVerdict verdict;
    SerialWrite("  verdict      : ");
    if (!any_val)
    {
        verdict = MachineCheckVerdict::NoError;
        SerialWrite("NO BANK VALID — spurious #MC or firmware-injected; "
                    "no hardware error recorded\n");
    }
    else if (any_pcc)
    {
        verdict = MachineCheckVerdict::ContextCorrupt;
        SerialWrite("PROCESSOR CONTEXT CORRUPT (PCC=1) — unrecoverable\n");
    }
    else if ((mcg_status & kMcgStatusRipv) == 0)
    {
        verdict = MachineCheckVerdict::ContextLost;
        SerialWrite("EXECUTION CONTEXT LOST (RIPV=0) — cannot resume the "
                    "interrupted flow, unrecoverable\n");
    }
    else
    {
        verdict = MachineCheckVerdict::RestartableInfo;
        // v1 (record-only) page poison: if any bank carries an SRAR
        // class entry with a usable ADDRV, record the failing frame
        // on the poison list. Subsequent `FreeFrame` on that PFN
        // will drop the frame instead of returning it to the pool;
        // existing references in user/kernel mappings stay in place
        // (full v1 — PTE walk + signal — depends on rmap which the
        // v0 mm layer doesn't have yet). The verdict still resolves
        // to "halt" for the current fault because resuming the
        // interrupted load requires the rmap walk we don't have;
        // recording the PFN ensures a future reboot persistence
        // path (the /system/badmem-list follow-on) sees the frame.
        if (srar_present)
        {
            duetos::mm::PoisonFrame(srar_addr);
            SerialWrite("SRAR ADDRESS recorded on poison list — frame "
                        "excluded from future allocation, but v1 has no "
                        "rmap walk, so this boot still halts for data "
                        "integrity\n");
        }
        else
        {
            SerialWrite("RESTARTABLE in principle (RIPV=1, no PCC) — no "
                        "SRAR-class bank with ADDRV; halting for data "
                        "integrity\n");
        }
    }
    (void)any_uc;

    // Post-mortem ring + GDB break. KLOG carries the verdict for the
    // log buffer; the probe lets an attached GDB `b
    // duetos::debug::ProbeFire` halt at the exact #MC frame. Both are
    // cheap and the IST2 stack gives us the room to run them.
    KLOG_ERROR_V("arch/mce", "machine check — see ** MACHINE CHECK (#MC) ** dump (verdict)", static_cast<u64>(verdict));
    KBP_PROBE_V(::duetos::debug::ProbeId::kMachineCheck,
                static_cast<u64>(worst_bank) | (static_cast<u64>(verdict) << 32));

    return verdict;
}

} // namespace duetos::arch
