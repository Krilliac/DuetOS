/*
 * Serial-input pump.
 *
 * Polls COM1's RBR for incoming bytes and translates them into the
 * same kernel-shell API the PS/2 keyboard reader feeds (ShellFeedChar
 * / ShellBackspace / ShellSubmit / ShellHistoryPrev / ShellHistoryNext
 * / ShellTabComplete / ShellInterrupt). With this in place, a headless
 * QEMU run with `-serial stdio` is a real interactive session: bytes
 * the operator types at the host terminal arrive on COM1, get cooked
 * into shell input, and the shell's responses land back on the same
 * COM1 stream the operator was already watching.
 *
 * Why a polling thread and not an IRQ:
 *   The 16550 IRQ path needs IDT plumbing + IOAPIC routing + the
 *   serial output side coordinating against an IRQ that can fire
 *   mid-write. Polling at 50 Hz (one wake per ~20 ms) is well below
 *   any keystroke rate a human can produce, costs one INB per poll
 *   when idle, and shares zero state with the write path.
 *
 * Terminal protocol cooked here:
 *   - 0x0D CR or 0x0A LF                  -> ShellSubmit
 *   - 0x7F DEL or 0x08 BS                 -> ShellBackspace
 *   - 0x09 HT                             -> ShellTabComplete
 *   - 0x03 ETX (Ctrl-C)                   -> ShellInterrupt
 *   - 0x1B [ A / 0x1B [ B (arrow up/down) -> ShellHistoryPrev / Next
 *   - 0x1B [ C / 0x1B [ D                 -> swallowed (right/left)
 *   - 0x20..0x7E printable ASCII          -> ShellFeedChar
 *   - everything else                     -> dropped
 *
 * The escape-sequence state machine is intentionally tiny: ESC starts
 * a 3-byte capture window; if the next byte isn't '[', the ESC is
 * dropped and the byte is reprocessed as a fresh input. If the
 * captured triplet doesn't match a known sequence, all three bytes are
 * dropped. Real terminals send much more (function keys, mouse, OSC,
 * bracketed paste, ...) — none of it is meaningful to the v0 shell,
 * so dropping is correct.
 *
 * Thread context: kernel task created by `SerialInputStart` from
 * core::main right after the PS/2 kbd reader. Owns no shared state.
 *
 * Subsystem isolation: this file lives in the kernel proper. Win32
 * and Linux subsystems do not touch the shell line buffer; userland
 * stdin focus has its own path (ProcessFeedStdinFocusChar) and stays
 * routed off PS/2.
 */

#include "core/serial_input.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/console.h"
#include "sched/sched.h"
#include "shell/shell.h"

namespace duetos::core
{

namespace
{

// Small ESC-sequence state machine. Two states:
//   0: idle — every byte is processed as a fresh input.
//   1: saw 0x1B, awaiting '[' or some other CSI introducer.
//   2: saw "ESC [", awaiting the final byte (A/B/C/D/...).
enum class EscState : u8
{
    Idle = 0,
    AfterEsc = 1,
    AfterCsi = 2,
};

void HandleByte(u8 byte, EscState& esc)
{
    switch (esc)
    {
    case EscState::Idle:
        break;
    case EscState::AfterEsc:
        if (byte == '[')
        {
            esc = EscState::AfterCsi;
            return;
        }
        // Lone ESC followed by a non-'[': drop the ESC, fall
        // through and reprocess this byte as fresh input.
        esc = EscState::Idle;
        break;
    case EscState::AfterCsi:
        if (byte == 'A')
        {
            ShellHistoryPrev();
        }
        else if (byte == 'B')
        {
            ShellHistoryNext();
        }
        // 'C' (right) and 'D' (left) — swallowed; v0 shell has
        // no intra-line cursor. Other CSI finals (~, R, ...) also
        // drop here.
        esc = EscState::Idle;
        return;
    }

    if (byte == 0x1B)
    {
        esc = EscState::AfterEsc;
        return;
    }

    if (byte == '\r' || byte == '\n')
    {
        ShellSubmit();
        return;
    }

    if (byte == 0x7F || byte == 0x08)
    {
        ShellBackspace();
        return;
    }

    if (byte == 0x09)
    {
        ShellTabComplete();
        return;
    }

    if (byte == 0x03)
    {
        ShellInterrupt();
        return;
    }

    if (byte >= 0x20 && byte <= 0x7E)
    {
        ShellFeedChar(static_cast<char>(byte));
        return;
    }

    // Anything else (NUL, other C0 controls, raw 8-bit) — drop.
}

void SerialInputThread(void*)
{
    EscState esc = EscState::Idle;
    for (;;)
    {
        // Drain any pending bytes before yielding. The 16550 has a
        // 16-byte FIFO and a paste of "policy show\n" arrives in one
        // burst — process the whole burst per wakeup so the shell
        // sees the line atomically rather than across two ticks.
        for (;;)
        {
            const i32 b = arch::SerialReadByteNonblocking();
            if (b < 0)
            {
                break;
            }
            HandleByte(static_cast<u8>(b), esc);
        }
        // 50 Hz wake rate — half a tick at the 100 Hz scheduler
        // base. Comfortably faster than a human types, low enough
        // that idle CPU draw from this thread is negligible.
        sched::SchedSleepTicks(2);
    }
}

} // namespace

void SerialInputStart()
{
    // Mirror the shell-console scrollback to COM1 so the operator
    // sees command responses on the same stream they're typing
    // into. Without this, output is framebuffer-only — invisible
    // under `-display none`.
    drivers::video::ConsoleEnableSerialMirror(true);
    sched::SchedCreate(SerialInputThread, nullptr, "serial-input");
}

} // namespace duetos::core
