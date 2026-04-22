#include "tmpfs.h"

#include "../core/klog.h"

namespace customos::fs
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

} // namespace customos::fs
