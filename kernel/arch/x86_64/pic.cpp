#include "arch/x86_64/pic.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"

#include "log/klog.h"

namespace duetos::arch
{

namespace
{

constexpr u16 kPicMasterCmd = 0x20;
constexpr u16 kPicMasterData = 0x21;
constexpr u16 kPicSlaveCmd = 0xA0;
constexpr u16 kPicSlaveData = 0xA1;

constexpr u8 kIcw1Init = 0x11;  // ICW1: init + edge-triggered + cascade + ICW4
constexpr u8 kIcw4_8086 = 0x01; // ICW4: 8086/88 mode

// I/O wait — write to an unused port. Some chips need a dozen-cycle delay
// between back-to-back PIC writes; the trick is portable across any PC.
inline void IoWait()
{
    Outb(0x80, 0);
}

} // namespace

void PicDisable()
{
    // The PIC reconfigure is a multi-port-write sequence. If a hardware
    // IRQ is delivered between ICW1 (which puts the chip in init mode)
    // and ICW2 (which programs the new vector base), the chip's behaviour
    // is implementation-defined: some 8259 variants and some QEMU TCG
    // configurations have been observed to deliver a held line to the
    // PRE-init vector base. If that base is 0 (firmware never programmed
    // it), the IRQ lands at vector 0 = #DE handler. This was the root
    // cause of an early CI flake on QEMU TCG.
    //
    // Defence: hard-mask interrupts at the CPU level for the entire
    // sequence, AND mask every line at the chip level BEFORE the init
    // sequence begins. Belt and suspenders — either alone would fix the
    // observed flake; together they're robust against future emulator
    // quirks too.
    const u64 saved_rflags = ReadRflags();
    Cli();

    // OCW1 (chip-level mask) BEFORE ICW1. The data port is the OCW1
    // mask register while the chip is in operational mode, so this
    // write lands as "mask all lines" before we enter init.
    Outb(kPicMasterData, 0xFF);
    Outb(kPicSlaveData, 0xFF);

    // ICW1 — start the init sequence on both PICs.
    Outb(kPicMasterCmd, kIcw1Init);
    IoWait();
    Outb(kPicSlaveCmd, kIcw1Init);
    IoWait();

    // ICW2 — vector base. Master IRQ0..7 -> 0x20..0x27, slave IRQ8..15 ->
    // 0x28..0x2F. Matches the IDT slots installed in exceptions.S so a
    // stray pre-mask IRQ lands on a real (no-op) handler instead of
    // colliding with a CPU exception vector.
    Outb(kPicMasterData, 0x20);
    IoWait();
    Outb(kPicSlaveData, 0x28);
    IoWait();

    // ICW3 — wiring. Master tells slave it's on IR2; slave tells master
    // its cascade identity is 2.
    Outb(kPicMasterData, 0x04);
    IoWait();
    Outb(kPicSlaveData, 0x02);
    IoWait();

    // ICW4 — 8086/88 mode (vs MCS-80/85, which nobody runs anymore).
    Outb(kPicMasterData, kIcw4_8086);
    IoWait();
    Outb(kPicSlaveData, kIcw4_8086);
    IoWait();

    // OCW1 — re-mask every line on both chips. The init sequence
    // resets the IMR on some variants, so the pre-ICW1 mask doesn't
    // necessarily survive. From here on no IRQ from the 8259 reaches
    // the CPU.
    Outb(kPicMasterData, 0xFF);
    Outb(kPicSlaveData, 0xFF);

    // Restore the caller's interrupt-enable state. Most callers run
    // with IF=1 (kernel boot post-IDT-setup); preserving rflags lets
    // PicDisable be called from either context without surprising the
    // caller.
    if ((saved_rflags & (1ULL << 9)) != 0)
    {
        Sti();
    }

    core::Log(core::LogLevel::Info, "arch/pic", "8259 remapped (0x20..0x2F) and fully masked");
}

} // namespace duetos::arch
