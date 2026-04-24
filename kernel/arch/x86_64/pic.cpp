#include "pic.h"

#include "cpu.h"
#include "serial.h"

#include "../../core/klog.h"

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

    // OCW1 — mask every line on both chips. From here on no IRQ from the
    // 8259 reaches the CPU.
    Outb(kPicMasterData, 0xFF);
    Outb(kPicSlaveData, 0xFF);

    core::Log(core::LogLevel::Info, "arch/pic", "8259 remapped (0x20..0x2F) and fully masked");
}

} // namespace duetos::arch
