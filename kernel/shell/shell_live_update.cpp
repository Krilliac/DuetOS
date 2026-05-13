/*
 * DuetOS — kernel shell: live-update command.
 *
 * `live-update <subcommand>` — in-kernel half of the hot-reload
 * workflow that pairs with `tools/dev/live-update.sh` on the host.
 *
 * Subcommands:
 *
 *   live-update status
 *       Print the live-app slot table (name → last_pid → reload
 *       count) plus the canonical list of surfaces that are NOT
 *       hot-reloadable from this build (kernel core, scheduler,
 *       paging, IDT/GDT, in-kernel drivers, baked-in PE/ELF
 *       blobs). Use this to see what the running kernel will
 *       accept a reload for.
 *
 *   live-update reload <path>
 *       Re-spawn the userland image at `<path>` (tmpfs or ramfs).
 *       If a previous reload registered a pid for this slot, the
 *       old task is signalled for kill via SchedKillByPid before
 *       the new spawn runs. The new pid is recorded so the next
 *       reload retires it cleanly. ELF and PE/COFF images are
 *       both accepted; the dispatcher picks by header magic.
 *
 *   live-update restart-required [reason]
 *       Emit the canonical "[live-update] RESTART REQUIRED" line
 *       at WARN level so the host-side script (or CI grep) can
 *       confirm the operator was told. `reason` is appended for
 *       the operator's benefit; it has no semantic meaning.
 *
 * Why an explicit per-name slot table instead of "scan ps for a
 * task with this name": the slot tracks pids we OURSELVES spawned
 * through the reload primitive. A user task that happens to share
 * a name (e.g. a smoke spawn) doesn't get killed by an unrelated
 * `live-update reload`. The slot table is the source of truth for
 * "the last live-update spawn we own for this image".
 *
 * Slot table is TU-local — there is no kernel-wide consumer; the
 * only entry point is the dispatch case in shell_dispatch.cpp.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "loader/elf_loader.h"
#include "loader/pe_loader.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/ring3_smoke.h"
#include "sched/sched.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// Live-app registry. Small fixed table — the workflow only needs
// a handful of slots in flight at once, and a static array keeps
// the entire surface allocation-free + boot-deterministic. Slot
// names are sized to match kTmpFsNameMax so paths like
// "/tmp/<32-byte-leaf>" round-trip without truncation.
constexpr u32 kLiveSlotCount = 8;
constexpr u32 kLiveSlotNameMax = duetos::fs::kTmpFsNameMax;

struct LiveSlot
{
    bool in_use;
    char name[kLiveSlotNameMax]; // basename of the most recent reload path
    u64 last_pid;                // 0 if no spawn ever, or last spawn already retired
    u64 reload_count;            // monotonic — for ops to confirm the slot has been touched
};

LiveSlot g_live[kLiveSlotCount];

// Copy at most `cap-1` chars from `src` to `dst`, NUL-terminate.
// Used to populate slot name + sanitize tmpfs leaf names.
void CopyName(char* dst, const char* src, u32 cap)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

bool NamesEqual(const char* a, const char* b)
{
    for (u32 i = 0; i < kLiveSlotNameMax; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return true;
}

// Return the basename of `path` (chars after the last '/'). Used
// as the slot key so "/tmp/hello.elf" and "hello.elf" route to
// the same live-app slot.
const char* Basename(const char* path)
{
    const char* leaf = path;
    for (const char* p = path; *p != '\0'; ++p)
    {
        if (*p == '/')
            leaf = p + 1;
    }
    return leaf;
}

// Find the slot owning `name`, or nullptr if no slot is bound to
// it yet. Linear scan — kLiveSlotCount is 8.
LiveSlot* FindSlot(const char* name)
{
    for (u32 i = 0; i < kLiveSlotCount; ++i)
    {
        if (g_live[i].in_use && NamesEqual(g_live[i].name, name))
            return &g_live[i];
    }
    return nullptr;
}

// Find or allocate a slot for `name`. Returns nullptr only if
// the table is full AND no slot already owns `name` — at that
// point the operator either needs to retire a slot (kill the
// pid + clear) or rebuild + reboot to drop everything.
LiveSlot* GetOrAllocSlot(const char* name)
{
    LiveSlot* existing = FindSlot(name);
    if (existing != nullptr)
        return existing;
    for (u32 i = 0; i < kLiveSlotCount; ++i)
    {
        if (!g_live[i].in_use)
        {
            g_live[i].in_use = true;
            CopyName(g_live[i].name, name, kLiveSlotNameMax);
            g_live[i].last_pid = 0;
            g_live[i].reload_count = 0;
            return &g_live[i];
        }
    }
    return nullptr;
}

// Best-effort kill of the slot's prior pid. Doesn't block — the
// scheduler retires the task asynchronously. Prints the result
// so the operator sees why the slot wasn't reaped (Protected /
// Blocked / AlreadyDead are all non-fatal for the reload).
void RetirePriorPid(LiveSlot* slot)
{
    if (slot->last_pid == 0)
        return;
    const auto r = duetos::sched::SchedKillByPid(slot->last_pid);
    ConsoleWrite("[live-update] retire prior pid=");
    WriteU64Dec(slot->last_pid);
    ConsoleWrite(" -> ");
    ConsoleWriteln(duetos::sched::KillResultName(r));
    slot->last_pid = 0;
}

// Read the source bytes for a reload. tmpfs and ramfs both feed
// SpawnElf/Pe with a flat (ptr, len) — but tmpfs forces a copy
// (slot data is mutable) while ramfs we can hand directly. The
// caller picks the buffer it owns; we return the live (ptr, len)
// the spawn path will see.
//
// Returns false if the path doesn't resolve.
bool ResolveImage(const char* path, char* tmp_scratch, u32 tmp_cap, const u8** bytes_out, u64* len_out)
{
    *bytes_out = nullptr;
    *len_out = 0;
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* src = nullptr;
        u32 src_len = 0;
        if (!duetos::fs::TmpFsRead(tmp_leaf, &src, &src_len))
            return false;
        const u32 n = (src_len > tmp_cap) ? tmp_cap : src_len;
        for (u32 i = 0; i < n; ++i)
            tmp_scratch[i] = src[i];
        *bytes_out = reinterpret_cast<const u8*>(tmp_scratch);
        *len_out = n;
        return true;
    }
    const auto* root = duetos::fs::RamfsTrustedRoot();
    const auto* node = duetos::fs::VfsLookup(root, path, 128);
    if (node == nullptr || node->type != duetos::fs::RamfsNodeType::kFile)
        return false;
    *bytes_out = node->file_bytes;
    *len_out = node->file_size;
    return true;
}

// Returns true if `bytes` starts with the ELF64 magic.
bool LooksLikeElf64(const u8* bytes, u64 len)
{
    return len >= 5 && bytes[0] == 0x7F && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F' && bytes[4] == 2;
}

// Returns true if `bytes` starts with the MZ DOS stub. (Strict
// PE/COFF validation runs inside PeValidate after we route here.)
bool LooksLikePe(const u8* bytes, u64 len)
{
    return len >= 2 && bytes[0] == 'M' && bytes[1] == 'Z';
}

void SubcmdStatus()
{
    ConsoleWriteln("[live-update] in-kernel hot-reload status");
    ConsoleWriteln("[live-update] hot-reloadable: tmpfs (/tmp/<leaf>) and ramfs paths via");
    ConsoleWriteln("              `live-update reload <path>` — see `man live-update`");
    ConsoleWriteln("[live-update] NOT hot-reloadable in this build (rebuild + reboot QEMU):");
    ConsoleWriteln("              * kernel core (sched / mm / paging / IDT / GDT / APIC)");
    ConsoleWriteln("              * in-kernel drivers and subsystem dispatchers");
    ConsoleWriteln("              * boot loader and trap frames");
    ConsoleWriteln("              * userland binaries baked into the kernel image via");
    ConsoleWriteln("                `duetos_embed_blob` — change source then rebuild");
    ConsoleWriteln("[live-update] active slots:");
    u32 active = 0;
    for (u32 i = 0; i < kLiveSlotCount; ++i)
    {
        if (!g_live[i].in_use)
            continue;
        ++active;
        ConsoleWrite("              [");
        WriteU64Dec(i);
        ConsoleWrite("] ");
        ConsoleWrite(g_live[i].name);
        ConsoleWrite("  last_pid=");
        WriteU64Dec(g_live[i].last_pid);
        ConsoleWrite("  reloads=");
        WriteU64Dec(g_live[i].reload_count);
        ConsoleWriteChar('\n');
    }
    if (active == 0)
    {
        ConsoleWriteln("              (none — `live-update reload <path>` to populate)");
    }
}

void SubcmdReload(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("[live-update] USAGE: live-update reload <path>");
        ConsoleWriteln("              <path> is /tmp/<leaf> or a ramfs path");
        return;
    }
    const char* path = argv[2];
    const char* leaf = Basename(path);
    if (leaf[0] == '\0')
    {
        ConsoleWriteln("[live-update] BAD PATH (empty basename)");
        return;
    }
    LiveSlot* slot = GetOrAllocSlot(leaf);
    if (slot == nullptr)
    {
        ConsoleWrite("[live-update] slot table full (");
        WriteU64Dec(kLiveSlotCount);
        ConsoleWriteln(" in use) — operator must retire a slot first");
        return;
    }

    // tmpfs source copies into a stack scratch so the spawn path
    // sees a stable buffer for the duration of the parse. Sized
    // to the writable tmpfs ceiling. ramfs source bypasses the
    // copy; ResolveImage hands back the raw node pointer.
    char scratch[duetos::fs::kTmpFsContentMax];
    const u8* bytes = nullptr;
    u64 len = 0;
    if (!ResolveImage(path, scratch, sizeof(scratch), &bytes, &len))
    {
        ConsoleWrite("[live-update] no such path: ");
        ConsoleWriteln(path);
        return;
    }
    if (len == 0)
    {
        ConsoleWriteln("[live-update] empty image — refusing to spawn");
        return;
    }

    // Retire the prior spawn BEFORE the new one queues, so two
    // generations of the same image don't run together. Kill is
    // async; the scheduler reaps on next slot.
    RetirePriorPid(slot);

    u64 new_pid = 0;
    if (LooksLikeElf64(bytes, len))
    {
        const auto st = duetos::core::ElfValidate(bytes, len);
        if (st != duetos::core::ElfStatus::Ok)
        {
            ConsoleWrite("[live-update] invalid ELF: ");
            ConsoleWriteln(duetos::core::ElfStatusName(st));
            return;
        }
        new_pid =
            duetos::core::SpawnElfFile(leaf, bytes, len, duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                       duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
    }
    else if (LooksLikePe(bytes, len))
    {
        const auto st = duetos::core::PeValidate(bytes, len);
        if (st != duetos::core::PeStatus::Ok)
        {
            ConsoleWrite("[live-update] invalid PE: ");
            ConsoleWriteln(duetos::core::PeStatusName(st));
            return;
        }
        new_pid =
            duetos::core::SpawnPeFile(leaf, bytes, len, duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                      duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
    }
    else
    {
        ConsoleWrite("[live-update] unrecognised image (not ELF64 or PE/COFF): ");
        ConsoleWriteln(path);
        return;
    }

    if (new_pid == 0)
    {
        ConsoleWriteln("[live-update] SPAWN FAILED (OOM or bad image layout) — slot retained but unbound");
        return;
    }
    slot->last_pid = new_pid;
    slot->reload_count = slot->reload_count + 1;
    ConsoleWrite("[live-update] reloaded ");
    ConsoleWrite(leaf);
    ConsoleWrite("  pid=");
    WriteU64Dec(new_pid);
    ConsoleWrite("  reloads=");
    WriteU64Dec(slot->reload_count);
    ConsoleWriteChar('\n');
    KLOG_INFO_S("live-update", "reload spawned", "image", leaf);
}

void SubcmdRestartRequired(u32 argc, char** argv)
{
    // The exact wording matters: the host-side script greps for
    // "[live-update] RESTART REQUIRED" on the serial log to flag
    // a kernel-image change that the running QEMU cannot reflect.
    // Don't reword without updating tools/dev/live-update.sh.
    ConsoleWrite("[live-update] RESTART REQUIRED");
    if (argc >= 3)
    {
        ConsoleWrite(" — ");
        for (u32 i = 2; i < argc; ++i)
        {
            if (i > 2)
                ConsoleWriteChar(' ');
            ConsoleWrite(argv[i]);
        }
    }
    ConsoleWriteChar('\n');
    KLOG_WARN_S("live-update", "operator-flagged restart required", "reason", (argc >= 3) ? argv[2] : "(unspecified)");
}

void SubcmdHelp()
{
    ConsoleWriteln("live-update — in-kernel hot-reload primitive");
    ConsoleWriteln("usage:");
    ConsoleWriteln("  live-update status                       print slot table + classes");
    ConsoleWriteln("  live-update reload <path>                respawn an image, retiring prior pid");
    ConsoleWriteln("  live-update restart-required [reason]    emit canonical RESTART REQUIRED line");
    ConsoleWriteln("paths:");
    ConsoleWriteln("  /tmp/<leaf>     writable tmpfs slot (small images only — 512B cap)");
    ConsoleWriteln("  <ramfs-path>    read-only ramfs (any size; respawns the embedded image)");
    ConsoleWriteln("see also: tools/dev/live-update.sh (host-side companion).");
}

} // namespace

void CmdLiveUpdate(u32 argc, char** argv)
{
    if (argc < 2)
    {
        SubcmdHelp();
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "status"))
    {
        SubcmdStatus();
        return;
    }
    if (StrEq(sub, "reload"))
    {
        SubcmdReload(argc, argv);
        return;
    }
    if (StrEq(sub, "restart-required"))
    {
        SubcmdRestartRequired(argc, argv);
        return;
    }
    if (StrEq(sub, "help") || StrEq(sub, "-h") || StrEq(sub, "--help"))
    {
        SubcmdHelp();
        return;
    }
    ConsoleWrite("[live-update] unknown subcommand: ");
    ConsoleWriteln(sub);
    SubcmdHelp();
}

} // namespace duetos::core::shell::internal
