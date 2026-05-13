#include "fs/boot_slot.h"

#include "core/panic.h"
#include "log/klog.h"
#include "util/types.h"

namespace duetos::fs::boot_slot
{

namespace
{

bool IEqRange(const char* a, const u8* b, u64 len)
{
    u64 i = 0;
    for (; i < len; ++i)
    {
        char ca = a[i];
        if (ca == '\0')
            return false;
        char cb = static_cast<char>(b[i]);
        if (ca >= 'A' && ca <= 'Z')
            ca = char(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = char(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return a[i] == '\0';
}

Slot SlotFromText(const u8* val, u64 len)
{
    if (len == 1)
    {
        char c = static_cast<char>(val[0]);
        if (c >= 'A' && c <= 'Z')
            c = char(c - 'A' + 'a');
        if (c == 'a')
            return Slot::kA;
        if (c == 'b')
            return Slot::kB;
    }
    if (IEqRange("invalid", val, len) || IEqRange("none", val, len))
        return Slot::kInvalid;
    return Slot::kInvalid;
}

bool ParseUint(const u8* val, u64 len, u64* out)
{
    if (len == 0)
        return false;
    u64 v = 0;
    for (u64 i = 0; i < len; ++i)
    {
        if (val[i] < '0' || val[i] > '9')
            return false;
        v = v * 10 + static_cast<u64>(val[i] - '0');
    }
    *out = v;
    return true;
}

u64 AppendStr(u8* buf, u64 cap, u64 pos, const char* s)
{
    while (*s != '\0')
    {
        if (pos >= cap)
            return cap;
        buf[pos++] = static_cast<u8>(*s++);
    }
    return pos;
}

u64 AppendU64(u8* buf, u64 cap, u64 pos, u64 v)
{
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        char rev[24];
        u32 r = 0;
        while (v > 0)
        {
            rev[r++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (r > 0)
            tmp[n++] = rev[--r];
    }
    for (u32 i = 0; i < n; ++i)
    {
        if (pos >= cap)
            return cap;
        buf[pos++] = static_cast<u8>(tmp[i]);
    }
    return pos;
}

} // namespace

State Default()
{
    State s;
    s.active = Slot::kA;
    s.pending = Slot::kInvalid;
    s.last_healthy = Slot::kA;
    s.tries_remaining = 3;
    s.valid = true;
    for (u32 i = 0; i < sizeof(s._pad); ++i)
        s._pad[i] = 0;
    return s;
}

Slot Other(Slot s)
{
    if (s == Slot::kA)
        return Slot::kB;
    if (s == Slot::kB)
        return Slot::kA;
    return Slot::kInvalid;
}

const char* Name(Slot s)
{
    switch (s)
    {
    case Slot::kA:
        return "a";
    case Slot::kB:
        return "b";
    case Slot::kInvalid:
    default:
        return "?";
    }
}

bool Parse(const u8* buf, u64 buf_len, State* out)
{
    if (out == nullptr)
        return false;
    *out = Default();
    if (buf == nullptr || buf_len == 0)
    {
        out->valid = false;
        return false;
    }

    bool saw_active = false;
    const u8* p = buf;
    const u8* end = buf + buf_len;
    while (p < end)
    {
        const u8* line_start = p;
        while (p < end && *p != '\n')
            ++p;
        const u8* line_end = p;
        if (p < end)
            ++p;
        // Trim trailing whitespace + CR.
        while (line_end > line_start && (line_end[-1] == ' ' || line_end[-1] == '\t' || line_end[-1] == '\r'))
            --line_end;
        // Skip leading whitespace + comments + blanks.
        while (line_start < line_end && (*line_start == ' ' || *line_start == '\t'))
            ++line_start;
        if (line_start >= line_end || *line_start == '#')
            continue;
        // Find '='.
        const u8* eq = nullptr;
        for (const u8* q = line_start; q < line_end; ++q)
        {
            if (*q == '=')
            {
                eq = q;
                break;
            }
        }
        if (eq == nullptr)
            continue;
        const u8* k_end = eq;
        while (k_end > line_start && (k_end[-1] == ' ' || k_end[-1] == '\t'))
            --k_end;
        const u8* v_start = eq + 1;
        while (v_start < line_end && (*v_start == ' ' || *v_start == '\t'))
            ++v_start;
        const u64 k_len = static_cast<u64>(k_end - line_start);
        const u64 v_len = static_cast<u64>(line_end - v_start);

        if (IEqRange("active", line_start, k_len))
        {
            out->active = SlotFromText(v_start, v_len);
            saw_active = true;
        }
        else if (IEqRange("pending", line_start, k_len))
        {
            out->pending = SlotFromText(v_start, v_len);
        }
        else if (IEqRange("last_healthy", line_start, k_len))
        {
            out->last_healthy = SlotFromText(v_start, v_len);
        }
        else if (IEqRange("tries_remaining", line_start, k_len))
        {
            u64 v = 0;
            if (ParseUint(v_start, v_len, &v))
                out->tries_remaining = (v > 255) ? 255 : static_cast<u8>(v);
        }
        // Unknown keys are ignored — forward-compatible with
        // future fields a future installer might add.
    }
    if (!saw_active || out->active == Slot::kInvalid)
    {
        out->valid = false;
        return false;
    }
    out->valid = true;
    return true;
}

u64 Serialise(const State& state, u8* buf, u64 buf_cap)
{
    if (buf == nullptr || buf_cap < 64)
        return 0;
    if (state.active == Slot::kInvalid)
        return 0;
    u64 pos = 0;
    pos = AppendStr(buf, buf_cap, pos, "# duetos boot-slot state v1\n");
    pos = AppendStr(buf, buf_cap, pos, "active=");
    pos = AppendStr(buf, buf_cap, pos, Name(state.active));
    pos = AppendStr(buf, buf_cap, pos, "\npending=");
    pos = AppendStr(buf, buf_cap, pos, Name(state.pending));
    pos = AppendStr(buf, buf_cap, pos, "\ntries_remaining=");
    pos = AppendU64(buf, buf_cap, pos, static_cast<u64>(state.tries_remaining));
    pos = AppendStr(buf, buf_cap, pos, "\nlast_healthy=");
    pos = AppendStr(buf, buf_cap, pos, Name(state.last_healthy));
    pos = AppendStr(buf, buf_cap, pos, "\n");
    return (pos >= buf_cap) ? 0 : pos;
}

State BeginInstall(const State& cur, Slot target)
{
    State next = cur;
    next.pending = target;
    next.tries_remaining = 3;
    // `last_healthy` stays as the previous active — if `target`
    // fails, that's the slot we roll back to.
    next.valid = (target == Slot::kA || target == Slot::kB);
    return next;
}

State MarkHealthy(const State& cur, Slot running)
{
    State next = cur;
    if (cur.pending == running)
    {
        // The pending install just booted clean — promote it.
        next.active = running;
        next.pending = Slot::kInvalid;
        next.last_healthy = running;
        next.tries_remaining = 3;
    }
    else if (cur.active == running)
    {
        // Steady-state boot of the active slot.
        next.last_healthy = running;
    }
    // If `running` is neither active nor pending, do nothing —
    // probably a stale state file; caller decides whether to
    // refresh.
    return next;
}

State Rollback(const State& cur)
{
    State next = cur;
    if (cur.last_healthy != Slot::kInvalid)
        next.active = cur.last_healthy;
    next.pending = Slot::kInvalid;
    next.tries_remaining = 3;
    return next;
}

void SelfTest()
{
    // 1. Default state is self-consistent.
    State s = Default();
    if (!s.valid || s.active != Slot::kA || s.last_healthy != Slot::kA || s.pending != Slot::kInvalid)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Default state wrong");
    if (Other(Slot::kA) != Slot::kB || Other(Slot::kB) != Slot::kA)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Other() wrong");

    // 2. BeginInstall promotes pending.
    State after_install = BeginInstall(s, Slot::kB);
    if (after_install.active != Slot::kA || after_install.pending != Slot::kB)
        ::duetos::core::Panic("fs/boot_slot", "self-test: BeginInstall didn't set pending");

    // 3. MarkHealthy on pending → active.
    State after_healthy = MarkHealthy(after_install, Slot::kB);
    if (after_healthy.active != Slot::kB || after_healthy.pending != Slot::kInvalid ||
        after_healthy.last_healthy != Slot::kB)
        ::duetos::core::Panic("fs/boot_slot", "self-test: MarkHealthy didn't promote");

    // 4. Rollback restores last_healthy.
    State after_install_a = BeginInstall(after_healthy, Slot::kA);
    State after_rollback = Rollback(after_install_a);
    if (after_rollback.active != Slot::kB || after_rollback.pending != Slot::kInvalid)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Rollback didn't restore");

    // 5. Serialise + Parse round-trip.
    u8 buf[256];
    const u64 n = Serialise(after_healthy, buf, sizeof(buf));
    if (n == 0)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Serialise returned 0");
    State parsed;
    if (!Parse(buf, n, &parsed) || !parsed.valid)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Parse rejected our own output");
    if (parsed.active != after_healthy.active || parsed.pending != after_healthy.pending ||
        parsed.last_healthy != after_healthy.last_healthy || parsed.tries_remaining != after_healthy.tries_remaining)
        ::duetos::core::Panic("fs/boot_slot", "self-test: round-trip lost fields");

    // 6. Parse rejects empty / bogus input cleanly.
    State junk;
    if (Parse(nullptr, 0, &junk))
        ::duetos::core::Panic("fs/boot_slot", "self-test: Parse accepted null buffer");
    if (junk.valid)
        ::duetos::core::Panic("fs/boot_slot", "self-test: Parse left junk.valid set");

    KLOG_INFO("fs/boot_slot", "self-test PASS");
}

} // namespace duetos::fs::boot_slot
