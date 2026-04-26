#include "fs/tmpfs.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"

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

} // namespace duetos::fs
