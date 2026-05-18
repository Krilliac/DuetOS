#include "fs/tmpfs.h"

#include "arch/x86_64/serial.h"
#include "core/boot_cmdline.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "sync/spinlock.h"

namespace duetos::fs
{

namespace
{

struct TmpFsSlot
{
    bool in_use;
    u32 length;
    char name[kTmpFsNameMax];
    char content[kTmpFsContentMax];
};

constinit TmpFsSlot g_slots[kTmpFsSlotCount] = {};

bool NameEq(const char* a, const char* b)
{
    for (u32 i = 0; i < kTmpFsNameMax; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
        if (a[i] == '\0')
        {
            return true;
        }
    }
    // Both hit the cap without a NUL; treat as equal by length.
    return true;
}

// Permit only printable, path-safe characters in names. Rules out
// NULs, slashes (no nesting), and whitespace so names stay
// tokenizable by the shell. Empty names are rejected.
bool NameIsValid(const char* name)
{
    if (name == nullptr || name[0] == '\0')
    {
        return false;
    }
    for (u32 i = 0; i < kTmpFsNameMax; ++i)
    {
        const char c = name[i];
        if (c == '\0')
        {
            return i > 0;
        }
        if (c == '/' || c == ' ' || c == '\t')
        {
            return false;
        }
    }
    return false; // name too long (no NUL within cap)
}

void CopyName(const char* src, char* dst)
{
    u32 i = 0;
    for (; i + 1 < kTmpFsNameMax && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

TmpFsSlot* Find(const char* name)
{
    for (u32 i = 0; i < kTmpFsSlotCount; ++i)
    {
        if (g_slots[i].in_use && NameEq(g_slots[i].name, name))
        {
            return &g_slots[i];
        }
    }
    return nullptr;
}

TmpFsSlot* AllocSlot(const char* name)
{
    for (u32 i = 0; i < kTmpFsSlotCount; ++i)
    {
        if (!g_slots[i].in_use)
        {
            g_slots[i].in_use = true;
            g_slots[i].length = 0;
            CopyName(name, g_slots[i].name);
            g_slots[i].content[0] = '\0';
            return &g_slots[i];
        }
    }
    // Slot table exhausted (16 slots). Once-per-boot warn so we don't
    // flood under sustained pressure; the caller's nullptr return is
    // the actionable signal.
    KLOG_ONCE_WARN("fs/tmpfs", "slot table full; cannot allocate more files");
    return nullptr;
}

} // namespace

bool TmpFsTouch(const char* name)
{
    if (!NameIsValid(name))
    {
        return false;
    }
    if (Find(name) != nullptr)
    {
        return true; // already present — no-op, matches coreutils touch
    }
    return AllocSlot(name) != nullptr;
}

bool TmpFsWrite(const char* name, const char* bytes, u32 len)
{
    if (!NameIsValid(name))
    {
        return false;
    }
    // Null bytes with a non-zero length is a caller bug; treat
    // zero-length writes as legitimate truncation.
    if (bytes == nullptr && len > 0)
    {
        return false;
    }
    TmpFsSlot* s = Find(name);
    if (s == nullptr)
    {
        s = AllocSlot(name);
        if (s == nullptr)
        {
            return false;
        }
    }
    if (len > kTmpFsContentMax)
    {
        len = kTmpFsContentMax; // truncate — matches fs write semantics on a full device
    }
    for (u32 i = 0; i < len; ++i)
    {
        s->content[i] = bytes[i];
    }
    s->length = len;
    return true;
}

bool TmpFsAppend(const char* name, const char* bytes, u32 len)
{
    if (!NameIsValid(name))
    {
        return false;
    }
    if (bytes == nullptr && len > 0)
    {
        return false;
    }
    TmpFsSlot* s = Find(name);
    if (s == nullptr)
    {
        s = AllocSlot(name);
        if (s == nullptr)
        {
            return false;
        }
    }
    u32 written = 0;
    while (written < len && s->length < kTmpFsContentMax)
    {
        s->content[s->length++] = bytes[written++];
    }
    return written > 0;
}

bool TmpFsRead(const char* name, const char** bytes_out, u32* len_out)
{
    TmpFsSlot* s = Find(name);
    if (s == nullptr)
    {
        return false;
    }
    if (bytes_out != nullptr)
    {
        *bytes_out = s->content;
    }
    if (len_out != nullptr)
    {
        *len_out = s->length;
    }
    return true;
}

bool TmpFsUnlink(const char* name)
{
    TmpFsSlot* s = Find(name);
    if (s == nullptr)
    {
        return false;
    }
    s->in_use = false;
    s->length = 0;
    s->name[0] = '\0';
    return true;
}

bool TmpFsRename(const char* src, const char* dst)
{
    if (!NameIsValid(src) || !NameIsValid(dst))
    {
        return false;
    }
    if (Find(dst) != nullptr)
    {
        return false; // refuse implicit overwrite
    }
    TmpFsSlot* s = Find(src);
    if (s == nullptr)
    {
        return false;
    }
    // Stamp the new name into the slot in place. No content
    // copy, no metadata fix-ups — tmpfs has neither parent
    // pointers nor link counts. The single store flips the
    // slot's identity atomically from the perspective of any
    // other tmpfs caller (tmpfs has no IRQ-side mutators).
    u32 i = 0;
    for (; i + 1 < kTmpFsNameMax && dst[i] != '\0'; ++i)
    {
        s->name[i] = dst[i];
    }
    s->name[i] = '\0';
    return true;
}

void TmpFsEnumerate(TmpFsEnumCb cb, void* cookie)
{
    if (cb == nullptr)
    {
        return;
    }
    for (u32 i = 0; i < kTmpFsSlotCount; ++i)
    {
        if (g_slots[i].in_use)
        {
            cb(g_slots[i].name, g_slots[i].length, cookie);
        }
    }
}

void TmpFsSelfTest()
{
    using duetos::arch::SerialWrite;

    // Walk every slot once, recording which slots were already
    // live before we ran so we can leave them untouched. The
    // self-test is intended to run at boot before the shell /
    // pipe path start populating tmpfs, but a stale slot from
    // a repeated self-test call shouldn't wedge the system.
    bool pre_in_use[kTmpFsSlotCount];
    u32 pre_live = 0;
    for (u32 i = 0; i < kTmpFsSlotCount; ++i)
    {
        pre_in_use[i] = g_slots[i].in_use;
        if (g_slots[i].in_use)
        {
            ++pre_live;
        }
    }

    bool pass = true;
    u32 failed_step = 0;
    auto mark_fail = [&](u32 step)
    {
        if (pass)
        {
            pass = false;
            failed_step = step;
        }
    };

    // A stable set of names owned by this test. Chosen to not
    // collide with any well-known boot-time tmpfs user ("__pipe__").
    const char* const kNameA = "__selftest_a";
    const char* const kNameB = "__selftest_b";
    const char* kNameC = "__selftest_c";

    const char* out_bytes = nullptr;
    u32 out_len = 0;

    // 1. Touch on a fresh name creates an empty file.
    if (!TmpFsTouch(kNameA))
        mark_fail(1);
    if (pass && (!TmpFsRead(kNameA, &out_bytes, &out_len) || out_len != 0))
        mark_fail(1);

    // 2. Touch on an existing name is a no-op success.
    if (pass && !TmpFsTouch(kNameA))
        mark_fail(2);

    // 3. Write overwrites and sets length.
    if (pass)
    {
        const char payload[] = "hello";
        if (!TmpFsWrite(kNameA, payload, 5))
            mark_fail(3);
        if (pass &&
            (!TmpFsRead(kNameA, &out_bytes, &out_len) || out_len != 5 || out_bytes[0] != 'h' || out_bytes[4] != 'o'))
            mark_fail(3);
    }

    // 4. Append grows length and preserves the prefix.
    if (pass)
    {
        const char payload[] = "!world";
        if (!TmpFsAppend(kNameA, payload, 6))
            mark_fail(4);
        if (pass && (!TmpFsRead(kNameA, &out_bytes, &out_len) || out_len != 11 || out_bytes[5] != '!'))
            mark_fail(4);
    }

    // 5. Append truncates at kTmpFsContentMax and reports bytes_written>0
    // on partial writes; a fully-full file refuses further appends.
    if (pass)
    {
        if (!TmpFsWrite(kNameB, nullptr, 0))
            mark_fail(5);
        // Fill to cap in large chunks of a single byte pattern.
        char chunk[128];
        for (u32 i = 0; i < sizeof(chunk); ++i)
            chunk[i] = 'x';
        u32 filled = 0;
        while (filled < kTmpFsContentMax)
        {
            u32 want = kTmpFsContentMax - filled;
            if (want > sizeof(chunk))
                want = sizeof(chunk);
            if (!TmpFsAppend(kNameB, chunk, want))
            {
                mark_fail(5);
                break;
            }
            filled += want;
        }
        if (pass && (!TmpFsRead(kNameB, &out_bytes, &out_len) || out_len != kTmpFsContentMax))
            mark_fail(5);
        // Further append should return false (zero bytes written).
        if (pass && TmpFsAppend(kNameB, "overflow", 8))
            mark_fail(5);
    }

    // 6. Oversized Write truncates to the cap.
    if (pass)
    {
        // Use a stack-cap chunk sized so it doesn't blow the
        // kernel boot stack: kTmpFsContentMax is 512 bytes.
        char oversized[kTmpFsContentMax + 16];
        for (u32 i = 0; i < sizeof(oversized); ++i)
            oversized[i] = 'z';
        if (!TmpFsWrite(kNameC, oversized, sizeof(oversized)))
            mark_fail(6);
        if (pass && (!TmpFsRead(kNameC, &out_bytes, &out_len) || out_len != kTmpFsContentMax))
            mark_fail(6);
    }

    // 7. Enumerate sees each of our three files + whatever was
    // there pre-test. Use a small context cookie that counts
    // hits for the three known names.
    if (pass)
    {
        struct Ctx
        {
            const char* a;
            const char* b;
            const char* c;
            u32 hits_a;
            u32 hits_b;
            u32 hits_c;
            u32 total;
        };
        Ctx ctx = {kNameA, kNameB, kNameC, 0, 0, 0, 0};
        auto cb = [](const char* name, u32 /*len*/, void* cookie_v)
        {
            auto* c = static_cast<Ctx*>(cookie_v);
            ++c->total;
            if (NameEq(name, c->a))
                ++c->hits_a;
            if (NameEq(name, c->b))
                ++c->hits_b;
            if (NameEq(name, c->c))
                ++c->hits_c;
        };
        TmpFsEnumerate(cb, &ctx);
        if (ctx.hits_a != 1 || ctx.hits_b != 1 || ctx.hits_c != 1 || ctx.total != pre_live + 3)
            mark_fail(7);
    }

    // 8. Unlink removes the file; subsequent Read fails.
    if (pass)
    {
        if (!TmpFsUnlink(kNameA))
            mark_fail(8);
        if (pass && TmpFsRead(kNameA, nullptr, nullptr))
            mark_fail(8);
        // Double-unlink reports false.
        if (pass && TmpFsUnlink(kNameA))
            mark_fail(8);
    }

    // 9. Name validation — empty / slash / whitespace / null
    // are all rejected.
    if (pass)
    {
        if (TmpFsTouch("") || TmpFsTouch("a/b") || TmpFsTouch("with space") || TmpFsTouch(nullptr))
            mark_fail(9);
    }

    // Clean up our two remaining test files so pre_in_use ==
    // post state.
    TmpFsUnlink(kNameB);
    TmpFsUnlink(kNameC);

    // 10. Post-condition: no additional slots should be live.
    if (pass)
    {
        u32 post_live = 0;
        for (u32 i = 0; i < kTmpFsSlotCount; ++i)
        {
            if (g_slots[i].in_use)
                ++post_live;
        }
        if (post_live != pre_live)
            mark_fail(10);
        // Every pre-existing slot must still be in use.
        for (u32 i = 0; i < kTmpFsSlotCount && pass; ++i)
        {
            if (pre_in_use[i] && !g_slots[i].in_use)
                mark_fail(10);
        }
    }

    if (pass)
    {
        SerialWrite("[tmpfs] self-test OK (touch+write+append+read+enum+unlink+validate)\n");
    }
    else
    {
        char msg[64] = "[tmpfs] self-test FAILED at step ";
        u32 o = 33;
        if (failed_step >= 10)
        {
            msg[o++] = static_cast<char>('0' + (failed_step / 10));
        }
        msg[o++] = static_cast<char>('0' + (failed_step % 10));
        msg[o++] = '\n';
        msg[o] = '\0';
        SerialWrite(msg);
    }
}

// ===========================================================================
// RamVol — frame-backed hierarchical sealable quota'd RAM volume.
// Additive; shares the module but touches none of the legacy state.
// ===========================================================================
namespace
{

constexpr u64 kRamFrameBytes = duetos::mm::kPageSize; // 4096

enum class RamKind : u8
{
    Dir,
    File,
};

struct RamNode
{
    RamKind kind;
    bool sealed;
    char name[kRamVolNameMax];
    RamNode* parent;
    RamNode* sibling; // next child of `parent`
    RamNode* child;   // first child (Dir only)
    u64 size;         // logical bytes (File only)
    mm::PhysAddr* frames;
    u32 frame_count; // frames currently backing the file
    u32 frame_cap;   // capacity of the `frames` array
};

constinit RamNode* g_ram_root = nullptr;
constinit u64 g_ram_quota_bytes = 0;
constinit u64 g_ram_used_bytes = 0; // sum of backing-frame bytes
constinit bool g_ram_inited = false;
constinit sync::SpinLock g_ram_lock{};

u64 RamStrLen(const char* s)
{
    u64 n = 0;
    while (s != nullptr && s[n] != '\0')
    {
        ++n;
    }
    return n;
}

bool RamNameValid(const char* s, u64 n)
{
    if (s == nullptr || n == 0 || n >= kRamVolNameMax)
    {
        return false;
    }
    for (u64 i = 0; i < n; ++i)
    {
        const char c = s[i];
        if (c == '/' || c == '\0')
        {
            return false;
        }
    }
    return true;
}

void RamCopyName(char* dst, const char* src, u64 n)
{
    for (u64 i = 0; i < n; ++i)
    {
        dst[i] = src[i];
    }
    dst[n] = '\0';
}

bool RamNameEq(const char* a, const char* b, u64 blen)
{
    if (RamStrLen(a) != blen)
    {
        return false;
    }
    for (u64 i = 0; i < blen; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
    }
    return true;
}

RamNode* RamChildLookup(RamNode* dir, const char* name, u64 name_len)
{
    if (dir == nullptr || dir->kind != RamKind::Dir)
    {
        return nullptr;
    }
    for (RamNode* c = dir->child; c != nullptr; c = c->sibling)
    {
        if (RamNameEq(c->name, name, name_len))
        {
            return c;
        }
    }
    return nullptr;
}

RamNode* RamAllocNode(RamKind kind, const char* name, u64 name_len, RamNode* parent)
{
    auto* n = static_cast<RamNode*>(mm::KMalloc(sizeof(RamNode)));
    if (n == nullptr)
    {
        return nullptr;
    }
    n->kind = kind;
    n->sealed = false;
    RamCopyName(n->name, name, name_len);
    n->parent = parent;
    n->sibling = nullptr;
    n->child = nullptr;
    n->size = 0;
    n->frames = nullptr;
    n->frame_count = 0;
    n->frame_cap = 0;
    if (parent != nullptr)
    {
        n->sibling = parent->child;
        parent->child = n;
    }
    return n;
}

// Walk `path` from the root. When `want_parent` is set, stop at
// the last component and return its PARENT, writing the final
// component name + length to `leaf`/`leaf_len`. Otherwise return
// the node the whole path names. nullptr on any miss / bad path.
RamNode* RamWalk(const char* path, bool want_parent, const char** leaf, u64* leaf_len)
{
    if (path == nullptr || path[0] != '/' || g_ram_root == nullptr)
    {
        return nullptr;
    }
    RamNode* cur = g_ram_root;
    u64 i = 1; // skip leading '/'
    while (true)
    {
        while (path[i] == '/')
        {
            ++i; // collapse repeated slashes
        }
        if (path[i] == '\0')
        {
            return want_parent ? nullptr : cur; // path was "/" or trailing slashes
        }
        u64 start = i;
        while (path[i] != '\0' && path[i] != '/')
        {
            ++i;
        }
        const u64 seg_len = i - start;
        // Is this the last component?
        u64 j = i;
        while (path[j] == '/')
        {
            ++j;
        }
        const bool last = (path[j] == '\0');
        if (last && want_parent)
        {
            if (cur->kind != RamKind::Dir || !RamNameValid(&path[start], seg_len))
            {
                return nullptr;
            }
            *leaf = &path[start];
            *leaf_len = seg_len;
            return cur;
        }
        RamNode* next = RamChildLookup(cur, &path[start], seg_len);
        if (next == nullptr)
        {
            return nullptr;
        }
        cur = next;
        if (last)
        {
            return cur;
        }
    }
}

// Ensure the file is backed by at least `need_frames` frames.
// Charges the quota per newly-allocated frame; rolls back and
// returns false if the quota would be exceeded or a frame alloc
// fails (leaving the file unchanged).
bool RamEnsureFrames(RamNode* f, u32 need_frames)
{
    if (need_frames <= f->frame_count)
    {
        return true;
    }
    const u32 add = need_frames - f->frame_count;
    if (g_ram_used_bytes + static_cast<u64>(add) * kRamFrameBytes > g_ram_quota_bytes)
    {
        return false; // quota
    }
    if (need_frames > f->frame_cap)
    {
        u32 new_cap = (f->frame_cap == 0) ? 8u : f->frame_cap * 2u;
        while (new_cap < need_frames)
        {
            new_cap *= 2u;
        }
        auto* na = static_cast<mm::PhysAddr*>(mm::KMalloc(sizeof(mm::PhysAddr) * new_cap));
        if (na == nullptr)
        {
            return false;
        }
        for (u32 k = 0; k < f->frame_count; ++k)
        {
            na[k] = f->frames[k];
        }
        if (f->frames != nullptr)
        {
            mm::KFree(f->frames);
        }
        f->frames = na;
        f->frame_cap = new_cap;
    }
    for (u32 k = f->frame_count; k < need_frames; ++k)
    {
        mm::PhysAddr p = mm::AllocateFrame();
        if (p == mm::kNullFrame)
        {
            return false; // OOM; previously-added frames stay (still owned/usable)
        }
        auto* v = static_cast<u8*>(mm::PhysToVirt(p));
        for (u64 b = 0; b < kRamFrameBytes; ++b)
        {
            v[b] = 0;
        }
        f->frames[k] = p;
        ++f->frame_count;
        g_ram_used_bytes += kRamFrameBytes;
    }
    return true;
}

void RamFreeFrames(RamNode* f)
{
    for (u32 k = 0; k < f->frame_count; ++k)
    {
        mm::FreeFrame(f->frames[k]);
        g_ram_used_bytes -= kRamFrameBytes;
    }
    if (f->frames != nullptr)
    {
        mm::KFree(f->frames);
    }
    f->frames = nullptr;
    f->frame_count = 0;
    f->frame_cap = 0;
}

void RamUnlinkChild(RamNode* parent, RamNode* victim)
{
    RamNode** pp = &parent->child;
    while (*pp != nullptr && *pp != victim)
    {
        pp = &(*pp)->sibling;
    }
    if (*pp == victim)
    {
        *pp = victim->sibling;
    }
}

// Resolve-or-create a regular file at `path` (parent must exist).
RamNode* RamFileForWrite(const char* path)
{
    RamNode* existing = RamWalk(path, false, nullptr, nullptr);
    if (existing != nullptr)
    {
        return (existing->kind == RamKind::File) ? existing : nullptr;
    }
    const char* leaf = nullptr;
    u64 leaf_len = 0;
    RamNode* parent = RamWalk(path, true, &leaf, &leaf_len);
    if (parent == nullptr)
    {
        return nullptr;
    }
    return RamAllocNode(RamKind::File, leaf, leaf_len, parent);
}

u64 ParseRamfsMib(uptr mb_info_phys)
{
    const char* cl = core::FindBootCmdline(mb_info_phys);
    if (cl == nullptr)
    {
        return kRamVolDefaultQuotaMib;
    }
    const char key[] = "ramfs-mib=";
    const u64 klen = sizeof(key) - 1;
    for (u64 i = 0; cl[i] != '\0'; ++i)
    {
        bool hit = (i == 0 || cl[i - 1] == ' ');
        for (u64 k = 0; hit && k < klen; ++k)
        {
            if (cl[i + k] != key[k])
            {
                hit = false;
            }
        }
        if (!hit)
        {
            continue;
        }
        u64 v = 0;
        u64 p = i + klen;
        bool any = false;
        while (cl[p] >= '0' && cl[p] <= '9')
        {
            v = v * 10 + static_cast<u64>(cl[p] - '0');
            ++p;
            any = true;
        }
        if (any && v > 0)
        {
            return v;
        }
        break;
    }
    return kRamVolDefaultQuotaMib;
}

} // namespace

void RamVolInit(uptr mb_info_phys)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    if (g_ram_inited)
    {
        return;
    }
    u64 mib = ParseRamfsMib(mb_info_phys);
    u64 quota = mib * 1024ull * 1024ull;
    // Clamp to <= 25% of free physical RAM so a tiny box scales
    // down and the volume can never over-commit the kernel.
    const u64 free_bytes = mm::FreeFramesCount() * kRamFrameBytes;
    const u64 cap = free_bytes / 4;
    if (quota > cap)
    {
        quota = cap;
    }
    g_ram_quota_bytes = quota;
    g_ram_used_bytes = 0;
    g_ram_root = RamAllocNode(RamKind::Dir, "", 0, nullptr);
    g_ram_inited = (g_ram_root != nullptr);
    if (g_ram_inited)
    {
        // Directory skeleton for services.
        RamNode* run = RamAllocNode(RamKind::Dir, "run", 3, g_ram_root);
        if (run != nullptr)
        {
            RamAllocNode(RamKind::Dir, "lock", 4, run);
        }
        RamAllocNode(RamKind::Dir, "tmp", 3, g_ram_root);
        KLOG_INFO_2V("fs/ramvol", "online", "quota_mib", quota / (1024ull * 1024ull), "free_mib",
                     free_bytes / (1024ull * 1024ull));
    }
}

bool RamVolMkdir(const char* path)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    if (RamWalk(path, false, nullptr, nullptr) != nullptr)
    {
        return false; // exists
    }
    const char* leaf = nullptr;
    u64 leaf_len = 0;
    RamNode* parent = RamWalk(path, true, &leaf, &leaf_len);
    if (parent == nullptr)
    {
        return false;
    }
    return RamAllocNode(RamKind::Dir, leaf, leaf_len, parent) != nullptr;
}

bool RamVolCreate(const char* path)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    return RamFileForWrite(path) != nullptr;
}

i64 RamVolWrite(const char* path, u64 offset, const void* buf, u64 len)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamFileForWrite(path);
    if (f == nullptr || f->sealed || buf == nullptr)
    {
        return -1;
    }
    if (len == 0)
    {
        return 0;
    }
    const u64 end = offset + len;
    const u32 need = static_cast<u32>((end + kRamFrameBytes - 1) / kRamFrameBytes);
    if (!RamEnsureFrames(f, need))
    {
        return -1; // quota / OOM
    }
    const auto* src = static_cast<const u8*>(buf);
    for (u64 w = 0; w < len; ++w)
    {
        const u64 pos = offset + w;
        auto* fv = static_cast<u8*>(mm::PhysToVirt(f->frames[pos / kRamFrameBytes]));
        fv[pos % kRamFrameBytes] = src[w];
    }
    if (end > f->size)
    {
        f->size = end;
    }
    return static_cast<i64>(len);
}

i64 RamVolAppend(const char* path, const void* buf, u64 len)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamFileForWrite(path);
    if (f == nullptr)
    {
        return -1;
    }
    return RamVolWrite(path, f->size, buf, len);
}

i64 RamVolRead(const char* path, u64 offset, void* buf, u64 len)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamWalk(path, false, nullptr, nullptr);
    if (f == nullptr || f->kind != RamKind::File || buf == nullptr)
    {
        return -1;
    }
    if (offset >= f->size || len == 0)
    {
        return 0;
    }
    u64 n = f->size - offset;
    if (n > len)
    {
        n = len;
    }
    auto* dst = static_cast<u8*>(buf);
    for (u64 r = 0; r < n; ++r)
    {
        const u64 pos = offset + r;
        const auto* fv = static_cast<const u8*>(mm::PhysToVirt(f->frames[pos / kRamFrameBytes]));
        dst[r] = fv[pos % kRamFrameBytes];
    }
    return static_cast<i64>(n);
}

bool RamVolTruncate(const char* path, u64 new_size)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamWalk(path, false, nullptr, nullptr);
    if (f == nullptr || f->kind != RamKind::File || f->sealed)
    {
        return false;
    }
    const u32 need = static_cast<u32>((new_size + kRamFrameBytes - 1) / kRamFrameBytes);
    if (need < f->frame_count)
    {
        for (u32 k = need; k < f->frame_count; ++k)
        {
            mm::FreeFrame(f->frames[k]);
            g_ram_used_bytes -= kRamFrameBytes;
        }
        f->frame_count = need;
    }
    else if (need > f->frame_count)
    {
        if (!RamEnsureFrames(f, need))
        {
            return false;
        }
    }
    f->size = new_size;
    return true;
}

bool RamVolUnlink(const char* path)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamWalk(path, false, nullptr, nullptr);
    if (f == nullptr || f->kind != RamKind::File || f->sealed)
    {
        return false;
    }
    RamFreeFrames(f);
    if (f->parent != nullptr)
    {
        RamUnlinkChild(f->parent, f);
    }
    mm::KFree(f);
    return true;
}

bool RamVolRmdir(const char* path)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* d = RamWalk(path, false, nullptr, nullptr);
    if (d == nullptr || d->kind != RamKind::Dir || d->child != nullptr || d == g_ram_root)
    {
        return false;
    }
    if (d->parent != nullptr)
    {
        RamUnlinkChild(d->parent, d);
    }
    mm::KFree(d);
    return true;
}

bool RamVolSeal(const char* path)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* f = RamWalk(path, false, nullptr, nullptr);
    if (f == nullptr || f->kind != RamKind::File)
    {
        return false;
    }
    f->sealed = true; // one-way
    return true;
}

bool RamVolStat(const char* path, u64* size_out, bool* is_dir_out, bool* sealed_out)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* n = RamWalk(path, false, nullptr, nullptr);
    if (n == nullptr)
    {
        return false;
    }
    if (size_out != nullptr)
    {
        *size_out = n->size;
    }
    if (is_dir_out != nullptr)
    {
        *is_dir_out = (n->kind == RamKind::Dir);
    }
    if (sealed_out != nullptr)
    {
        *sealed_out = n->sealed;
    }
    return true;
}

void RamVolReaddir(const char* path, RamVolEnumCb cb, void* cookie)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    RamNode* d = RamWalk(path, false, nullptr, nullptr);
    if (d == nullptr || d->kind != RamKind::Dir || cb == nullptr)
    {
        return;
    }
    for (RamNode* c = d->child; c != nullptr; c = c->sibling)
    {
        cb(c->name, c->size, c->kind == RamKind::Dir, c->sealed, cookie);
    }
}

void RamVolStats(u64* used_bytes_out, u64* quota_bytes_out)
{
    sync::SpinLockRecursiveGuard g(g_ram_lock);
    if (used_bytes_out != nullptr)
    {
        *used_bytes_out = g_ram_used_bytes;
    }
    if (quota_bytes_out != nullptr)
    {
        *quota_bytes_out = g_ram_quota_bytes;
    }
}

void RamVolSelfTest()
{
    using arch::SerialWrite;
    if (!g_ram_inited)
    {
        SerialWrite("[ramvol] self-test: SKIP (not initialised)\n");
        return;
    }

    auto fail = [&](const char* why)
    {
        SerialWrite("[ramvol] self-test: FAIL (");
        SerialWrite(why);
        SerialWrite(")\n");
    };

    // mkdir + create + write + read round-trip across a frame
    // boundary (write 5000 bytes => 2 frames).
    if (!RamVolMkdir("/run/selftest"))
    {
        return fail("mkdir");
    }
    static u8 src[5000];
    for (u32 i = 0; i < sizeof(src); ++i)
    {
        src[i] = static_cast<u8>(i * 7u + 3u);
    }
    if (RamVolWrite("/run/selftest/a", 0, src, sizeof(src)) != static_cast<i64>(sizeof(src)))
    {
        return fail("write");
    }
    static u8 back[5000];
    if (RamVolRead("/run/selftest/a", 0, back, sizeof(back)) != static_cast<i64>(sizeof(back)))
    {
        return fail("read len");
    }
    for (u32 i = 0; i < sizeof(src); ++i)
    {
        if (back[i] != src[i])
        {
            return fail("read mismatch");
        }
    }

    // append extends size; read picks up the tail.
    const char tail[] = "TAIL";
    if (RamVolAppend("/run/selftest/a", tail, 4) != 4)
    {
        return fail("append");
    }
    u64 sz = 0;
    if (!RamVolStat("/run/selftest/a", &sz, nullptr, nullptr) || sz != sizeof(src) + 4)
    {
        return fail("append size");
    }

    // truncate shrinks (and frees frames); stat reflects it.
    if (!RamVolTruncate("/run/selftest/a", 10) || !RamVolStat("/run/selftest/a", &sz, nullptr, nullptr) || sz != 10)
    {
        return fail("truncate");
    }

    // SEAL => write / truncate / unlink all rejected (Static mode).
    bool sealed = false;
    if (!RamVolSeal("/run/selftest/a") || !RamVolStat("/run/selftest/a", nullptr, nullptr, &sealed) || !sealed)
    {
        return fail("seal");
    }
    if (RamVolWrite("/run/selftest/a", 0, src, 4) != -1)
    {
        return fail("sealed write accepted");
    }
    if (RamVolTruncate("/run/selftest/a", 0) || RamVolUnlink("/run/selftest/a"))
    {
        return fail("sealed mutate accepted");
    }

    // quota rejection: a write past the quota is refused WITHOUT
    // allocating (pre-check), and the volume stays consistent.
    u64 used = 0, quota = 0;
    RamVolStats(&used, &quota);
    if (RamVolWrite("/run/selftest/big", 0, src, quota + 1) != -1)
    {
        return fail("quota not enforced");
    }
    u64 used_after = 0;
    RamVolStats(&used_after, nullptr);
    if (used_after != used)
    {
        return fail("quota reject leaked frames");
    }

    // An unsealed sibling still unlinks; rmdir needs it empty.
    if (!RamVolCreate("/run/selftest/b") || !RamVolUnlink("/run/selftest/b"))
    {
        return fail("unlink");
    }
    if (RamVolRmdir("/run/selftest"))
    {
        return fail("rmdir non-empty accepted"); // /a (sealed) still present
    }

    SerialWrite("[ramvol] self-test: PASS\n");
}

} // namespace duetos::fs
