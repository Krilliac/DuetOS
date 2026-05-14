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

#include "debug/hot_patch.h"
#include "drivers/video/console.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "loader/elf_loader.h"
#include "loader/pe_loader.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/spawn.h"
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

// Parse a base-10 u32. Returns false if the string isn't pure
// digits or overflows. Used by the kernel-revert path to take a
// patch handle from the operator.
bool ParseU32(const char* s, u32* out)
{
    if (s == nullptr || s[0] == '\0')
        return false;
    u64 v = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + static_cast<u64>(s[i] - '0');
        if (v > 0xFFFFFFFFULL)
            return false;
    }
    *out = static_cast<u32>(v);
    return true;
}

void SubcmdKernelPatch(u32 argc, char** argv)
{
    if (argc < 4)
    {
        ConsoleWriteln("[live-update] USAGE: live-update kernel-patch <target> <replacement>");
        ConsoleWriteln("              both args are fully-qualified kernel symbol names,");
        ConsoleWriteln("              e.g. duetos::debug::HotPatchTestTargetReturns7()");
        return;
    }
    duetos::debug::HotPatchHandle h{};
    const auto st = duetos::debug::HotPatchInstallByName(argv[2], argv[3], &h);
    if (st != duetos::debug::HotPatchStatus::Ok)
    {
        ConsoleWrite("[live-update] kernel-patch FAILED: ");
        ConsoleWriteln(duetos::debug::HotPatchStatusName(st));
        return;
    }
    ConsoleWrite("[live-update] kernel-patch OK  handle=");
    WriteU64Dec(h.id);
    ConsoleWrite("  ");
    ConsoleWrite(argv[2]);
    ConsoleWrite(" -> ");
    ConsoleWriteln(argv[3]);
}

void SubcmdKernelRevert(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("[live-update] USAGE: live-update kernel-revert <handle>");
        ConsoleWriteln("              `live-update kernel-patches` lists live handles");
        return;
    }
    u32 id = 0;
    if (!ParseU32(argv[2], &id) || id == 0)
    {
        ConsoleWriteln("[live-update] kernel-revert: bad handle");
        return;
    }
    duetos::debug::HotPatchHandle h{id};
    const auto st = duetos::debug::HotPatchRevert(h);
    if (st != duetos::debug::HotPatchStatus::Ok)
    {
        ConsoleWrite("[live-update] kernel-revert FAILED: ");
        ConsoleWriteln(duetos::debug::HotPatchStatusName(st));
        return;
    }
    ConsoleWrite("[live-update] kernel-revert OK  handle=");
    WriteU64Dec(id);
    ConsoleWriteChar('\n');
}

// Build-time identity of the currently-running kernel. All four
// preprocessor strings are baked in by the top-level CMakeLists.txt
// at configure time — see the "Git short hash + dirty flag" block.
// The fallback strings keep the output well-formed when CMake
// couldn't reach git or when the macros are missing for some reason
// (out-of-tree build, stripped define, etc.).
constexpr const char* BuildGitHash()
{
#if defined(DUETOS_GIT_HASH)
    return DUETOS_GIT_HASH;
#else
    return "(undefined)";
#endif
}
constexpr const char* BuildGitSubject()
{
#if defined(DUETOS_GIT_SUBJECT)
    return DUETOS_GIT_SUBJECT;
#else
    return "(undefined)";
#endif
}
constexpr const char* BuildGitBranch()
{
#if defined(DUETOS_GIT_BRANCH)
    return DUETOS_GIT_BRANCH;
#else
    return "(undefined)";
#endif
}
constexpr const char* BuildGitAuthorDate()
{
#if defined(DUETOS_GIT_AUTHOR_DATE)
    return DUETOS_GIT_AUTHOR_DATE;
#else
    return "(undefined)";
#endif
}
constexpr const char* BuildDate()
{
#if defined(DUETOS_BUILD_DATE)
    return DUETOS_BUILD_DATE;
#else
    return "(undefined)";
#endif
}

// One-line build identity. Cheap enough to print in front of every
// bulk operation; an operator who runs `kernel-auto-patch` on the
// wrong kernel can see immediately which build they hit.
void WriteBuildIdentityLine()
{
    ConsoleWrite("[live-update] running kernel  hash=");
    ConsoleWrite(BuildGitHash());
    ConsoleWrite("  branch=");
    ConsoleWrite(BuildGitBranch());
    ConsoleWriteChar('\n');
}

// Full multi-line build identity. Used by `live-update version`.
void WriteBuildIdentityBlock()
{
    ConsoleWrite("[live-update] running kernel build info:\n");
    ConsoleWrite("              hash        : ");
    ConsoleWriteln(BuildGitHash());
    ConsoleWrite("              branch      : ");
    ConsoleWriteln(BuildGitBranch());
    ConsoleWrite("              subject     : ");
    ConsoleWriteln(BuildGitSubject());
    ConsoleWrite("              author date : ");
    ConsoleWriteln(BuildGitAuthorDate());
    ConsoleWrite("              built       : ");
    ConsoleWriteln(BuildDate());
    ConsoleWriteln("              (configure-time capture — a trailing '+' on hash means");
    ConsoleWriteln("               the working tree had uncommitted edits at CMake configure)");
}

void SubcmdVersion()
{
    WriteBuildIdentityBlock();
    KLOG_INFO_S("live-update", "version queried", "hash", BuildGitHash());
}

void SubcmdKernelPatches()
{
    duetos::debug::HotPatchRecord rows[duetos::debug::kMaxLivePatches];
    const u32 n = duetos::debug::HotPatchEnumerate(rows, duetos::debug::kMaxLivePatches);
    ConsoleWrite("[live-update] live kernel patches: ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    if (n == 0)
    {
        ConsoleWriteln("              (none — `live-update kernel-patch <target> <replacement>` to install)");
        return;
    }
    for (u32 i = 0; i < n; ++i)
    {
        const auto& r = rows[i];
        ConsoleWrite("              handle=");
        WriteU64Dec(r.id);
        ConsoleWrite("  target=");
        ConsoleWrite(r.target_name != nullptr ? r.target_name : "??");
        ConsoleWrite("  ->  ");
        ConsoleWriteln(r.replacement_name != nullptr ? r.replacement_name : "??");
    }
}

void SubcmdKernelAutoPatch()
{
    WriteBuildIdentityLine();
    const auto r = duetos::debug::HotPatchApplyAll();
    ConsoleWrite("[live-update] kernel-auto-patch  considered=");
    WriteU64Dec(r.considered);
    ConsoleWrite("  installed=");
    WriteU64Dec(r.installed);
    ConsoleWrite("  already_patched=");
    WriteU64Dec(r.already_patched);
    ConsoleWrite("  failed=");
    WriteU64Dec(r.failed);
    ConsoleWriteChar('\n');
    if (r.installed > 0)
        KLOG_INFO_V("live-update", "kernel-auto-patch installed", r.installed);
    if (r.failed > 0)
        KLOG_WARN_V("live-update", "kernel-auto-patch failed pairs", r.failed);
}

void SubcmdKernelAutoRevert()
{
    WriteBuildIdentityLine();
    const auto r = duetos::debug::HotPatchRevertAll();
    ConsoleWrite("[live-update] kernel-auto-revert  considered=");
    WriteU64Dec(r.considered);
    ConsoleWrite("  reverted=");
    WriteU64Dec(r.reverted);
    ConsoleWrite("  failed=");
    WriteU64Dec(r.failed);
    ConsoleWriteChar('\n');
    if (r.reverted > 0)
        KLOG_INFO_V("live-update", "kernel-auto-revert reverted", r.reverted);
    if (r.failed > 0)
        KLOG_WARN_V("live-update", "kernel-auto-revert failed reverts", r.failed);
}

void SubcmdReloadAll()
{
    u32 attempted = 0;
    u32 succeeded = 0;
    u32 failed = 0;
    for (u32 i = 0; i < kLiveSlotCount; ++i)
    {
        if (!g_live[i].in_use)
            continue;
        ++attempted;
        // We need a source path to reload from. v0 LiveSlot
        // tracks only the basename, so we try /tmp/<basename>.
        // This works for the common workflow ("operator wrote
        // the new image to /tmp/<name> with the same basename
        // the slot already tracks") but doesn't recover slots
        // that originally loaded from an arbitrary ramfs path
        // — those need an explicit `live-update reload <path>`.
        char path_scratch[kLiveSlotNameMax + 8];
        u32 pi = 0;
        const char tmp_prefix[] = "/tmp/";
        for (u32 k = 0; k < sizeof(tmp_prefix) - 1; ++k)
            path_scratch[pi++] = tmp_prefix[k];
        for (u32 k = 0; k < kLiveSlotNameMax && g_live[i].name[k] != '\0'; ++k)
            path_scratch[pi++] = g_live[i].name[k];
        path_scratch[pi] = '\0';

        const u64 prev_pid = g_live[i].last_pid;
        char* argv2[3] = {const_cast<char*>("live-update"), const_cast<char*>("reload"), path_scratch};
        SubcmdReload(3, argv2);
        if (g_live[i].last_pid != prev_pid && g_live[i].last_pid != 0)
            ++succeeded;
        else
            ++failed;
    }
    ConsoleWrite("[live-update] reload-all  slots=");
    WriteU64Dec(attempted);
    ConsoleWrite("  succeeded=");
    WriteU64Dec(succeeded);
    ConsoleWrite("  failed=");
    WriteU64Dec(failed);
    ConsoleWriteChar('\n');
    if (attempted == 0)
        ConsoleWriteln("              (no live slots — use `reload <path>` first)");
}

void SubcmdHelp()
{
    ConsoleWriteln("live-update — in-kernel hot-reload + hot-patch primitive");
    ConsoleWriteln("usage:");
    ConsoleWriteln("  live-update version                           running kernel hash + commit subject");
    ConsoleWriteln("  live-update status                            slot table + classes");
    ConsoleWriteln("  live-update reload <path>                     respawn a userland image");
    ConsoleWriteln("  live-update reload-all                        respawn every live slot from /tmp/<name>");
    ConsoleWriteln("  live-update restart-required [reason]         emit canonical RESTART REQUIRED");
    ConsoleWriteln("  live-update kernel-patch <target> <repl>      JMP rel32 redirect (kernel .text)");
    ConsoleWriteln("  live-update kernel-revert <handle>            restore prior bytes for a patch");
    ConsoleWriteln("  live-update kernel-patches                    list live kernel patches");
    ConsoleWriteln("  live-update kernel-auto-patch                 install every registered patch pair");
    ConsoleWriteln("  live-update kernel-auto-revert                revert every live kernel patch");
    ConsoleWriteln("paths (for reload):");
    ConsoleWriteln("  /tmp/<leaf>     writable tmpfs slot (small images only — 512B cap)");
    ConsoleWriteln("  <ramfs-path>    read-only ramfs (any size; respawns the embedded image)");
    ConsoleWriteln("kernel patching:");
    ConsoleWriteln("  target must be declared KHOTPATCH_PATCHABLE in source;");
    ConsoleWriteln("  symbols are looked up in the embedded kernel symbol table.");
    ConsoleWriteln("  kernel-auto-patch walks the .duetos_hotpatch_pairs link-time registry");
    ConsoleWriteln("  (entries land via KHOTPATCH_REGISTER_PAIR in source).");
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
    if (StrEq(sub, "kernel-patch"))
    {
        SubcmdKernelPatch(argc, argv);
        return;
    }
    if (StrEq(sub, "kernel-revert"))
    {
        SubcmdKernelRevert(argc, argv);
        return;
    }
    if (StrEq(sub, "kernel-patches"))
    {
        SubcmdKernelPatches();
        return;
    }
    if (StrEq(sub, "version"))
    {
        SubcmdVersion();
        return;
    }
    if (StrEq(sub, "kernel-auto-patch"))
    {
        SubcmdKernelAutoPatch();
        return;
    }
    if (StrEq(sub, "kernel-auto-revert"))
    {
        SubcmdKernelAutoRevert();
        return;
    }
    if (StrEq(sub, "reload-all"))
    {
        SubcmdReloadAll();
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
