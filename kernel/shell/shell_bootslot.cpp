/*
 * DuetOS — kernel shell: A/B boot-slot commands.
 *
 * `slotinfo`        — print current slot state (active, pending,
 *                     last_healthy, tries_remaining, source).
 * `bootslot ...`    — administer the A/B layout:
 *     install <a|b> <kernel-path>   stage a kernel into the named slot
 *                                   and flip `pending` so the next boot
 *                                   tries it. Requires admin.
 *     rollback                      force `Rollback`: restore
 *                                   `last_healthy`, clear pending.
 *                                   Requires admin.
 *     force-fail                    test-only: write tries_remaining=0
 *                                   and reboot, so the bootloader path
 *                                   exercises rollback. Requires admin.
 *
 * Persistence: every state-changing subcommand routes through the
 * shared FAT32 bridge `installer::PersistSlotState`, which writes
 * /boot/duetos-slot.cfg AND regenerates /boot/grub/grub.cfg (on
 * ESP volumes) so GRUB's `set default` tracks the change.
 * Read-only commands (`slotinfo`) pull from the in-RAM
 * CurrentState only — they don't touch disk.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "fs/boot_slot.h"
#include "fs/installer.h"
#include "power/reboot.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteln;
namespace bs = ::duetos::fs::boot_slot;

bool PersistSlotState(const bs::State& st)
{
    const auto* vol = ::duetos::fs::installer::FindBootSlotVolume();
    if (vol == nullptr)
    {
        ConsoleWriteln("BOOTSLOT: no FAT32 volume — state NOT persisted");
        return false;
    }
    if (!::duetos::fs::installer::PersistSlotState(vol, st))
    {
        ConsoleWriteln("BOOTSLOT: persist write failed");
        return false;
    }
    return true;
}

bs::Slot SlotFromArg(const char* arg)
{
    if (arg == nullptr || arg[1] != '\0')
        return bs::Slot::kInvalid;
    const char c = (arg[0] >= 'A' && arg[0] <= 'Z') ? char(arg[0] + ('a' - 'A')) : arg[0];
    if (c == 'a')
        return bs::Slot::kA;
    if (c == 'b')
        return bs::Slot::kB;
    return bs::Slot::kInvalid;
}

void PrintSlot(const char* label, bs::Slot s)
{
    ConsoleWrite(label);
    ConsoleWrite("=");
    ConsoleWriteln(bs::Name(s));
}

} // namespace

void CmdSlotinfo()
{
    const auto st = bs::CurrentState();
    ConsoleWriteln("boot-slot state (in-RAM):");
    PrintSlot("  active       ", st.active);
    PrintSlot("  pending      ", st.pending);
    PrintSlot("  last_healthy ", st.last_healthy);
    ConsoleWrite("  tries_remaining=");
    WriteU64Dec(static_cast<u64>(st.tries_remaining));
    ConsoleWriteln("");
    ConsoleWrite("  valid        =");
    ConsoleWriteln(st.valid ? "true" : "false");
    ConsoleWrite("  state-file path=");
    ConsoleWriteln(bs::kSlotStateFilePath);
    ConsoleWrite("  kernel image   =");
    const char* p = bs::SlotKernelPath(st.active);
    ConsoleWriteln(p != nullptr ? p : "(invalid)");
}

void CmdBootslot(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("BOOTSLOT: USAGE: BOOTSLOT { install <a|b> <path> | rollback | force-fail }");
        return;
    }
    const char* sub = argv[1];

    if (StrEq(sub, "install"))
    {
        if (!RequireAdmin("BOOTSLOT"))
            return;
        if (argc < 4)
        {
            ConsoleWriteln("BOOTSLOT INSTALL: USAGE: BOOTSLOT INSTALL <a|b> <kernel-path>");
            return;
        }
        const bs::Slot target = SlotFromArg(argv[2]);
        if (target == bs::Slot::kInvalid)
        {
            ConsoleWriteln("BOOTSLOT INSTALL: slot must be 'a' or 'b'");
            return;
        }
        // We don't copy the kernel ELF here — that's the installer's
        // job, and may run from a different context (live-update,
        // duet-pkg). What we do is flip the state file so the next
        // boot tries `target` first. The caller is expected to have
        // staged the kernel image at the canonical SlotKernelPath
        // before invoking this command; we log the path for the
        // operator's benefit.
        auto cur = bs::CurrentState();
        const auto next = bs::BeginInstall(cur, target);
        if (!next.valid)
        {
            ConsoleWriteln("BOOTSLOT INSTALL: BeginInstall rejected");
            return;
        }
        bs::SetCurrentState(next);
        if (!PersistSlotState(next))
            return;
        ConsoleWrite("BOOTSLOT: install staged. pending=");
        ConsoleWrite(bs::Name(target));
        ConsoleWrite(" image=");
        ConsoleWriteln(argv[3]);
        return;
    }

    if (StrEq(sub, "rollback"))
    {
        if (!RequireAdmin("BOOTSLOT"))
            return;
        auto cur = bs::CurrentState();
        const auto next = bs::Rollback(cur);
        bs::SetCurrentState(next);
        if (!PersistSlotState(next))
            return;
        ConsoleWrite("BOOTSLOT: rolled back. active=");
        ConsoleWriteln(bs::Name(next.active));
        return;
    }

    if (StrEq(sub, "force-fail"))
    {
        if (!RequireAdmin("BOOTSLOT"))
            return;
        // Test-only: simulate a botched install by zeroing
        // tries_remaining for the current pending slot, then
        // rebooting. The bootloader is expected to observe
        // tries_remaining=0 and roll back to last_healthy on the
        // next boot. Useful for end-to-end rollback verification
        // from inside a running system.
        auto cur = bs::CurrentState();
        cur.tries_remaining = 0;
        bs::SetCurrentState(cur);
        if (!PersistSlotState(cur))
            return;
        ConsoleWriteln("BOOTSLOT: tries_remaining=0; rebooting to exercise rollback");
        ::duetos::core::KernelReboot();
    }

    ConsoleWrite("BOOTSLOT: unknown subcommand '");
    ConsoleWrite(sub);
    ConsoleWriteln("'");
}

} // namespace duetos::core::shell::internal
