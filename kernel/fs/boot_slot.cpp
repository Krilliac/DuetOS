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

namespace
{
// In-RAM current state. Default at boot; SetCurrentState replaces
// it when the bootloader hand-off lands the parsed on-disk
// state. Single-CPU access pattern under v0 — shell command +
// future watchdog both run in process / heartbeat context — so
// no lock yet.
constinit State g_current = {};
constinit bool g_current_initialised = false;

void EnsureInitialised()
{
    if (!g_current_initialised)
    {
        g_current = Default();
        g_current_initialised = true;
    }
}
} // namespace

State CurrentState()
{
    EnsureInitialised();
    return g_current;
}

void SetCurrentState(const State& state)
{
    g_current = state;
    g_current_initialised = true;
}

State MarkHealthyNow()
{
    EnsureInitialised();
    g_current = MarkHealthy(g_current, g_current.active);
    return g_current;
}

const char* SlotKernelPath(Slot s)
{
    switch (s)
    {
    case Slot::kA:
        return "/boot/duetos-kernel-a.elf";
    case Slot::kB:
        return "/boot/duetos-kernel-b.elf";
    case Slot::kInvalid:
    default:
        return nullptr;
    }
}

namespace
{

// menuentry index inside the generated grub.cfg. Slot A is always
// entry 0, slot B entry 1; the legacy single-kernel entry is 2.
char EntryIndexChar(Slot s)
{
    return (s == Slot::kB) ? '1' : '0';
}

} // namespace

u64 GrubCfgGenerate(const State& state, u8* buf, u64 buf_cap)
{
    if (buf == nullptr || buf_cap < 512)
        return 0;
    if (state.active != Slot::kA && state.active != Slot::kB)
        return 0;

    // The slot GRUB should try first: a pending install with tries
    // left wins; otherwise the active slot. `pending` with
    // tries_remaining == 0 means the install exhausted its attempts
    // (`bootslot force-fail` writes exactly this shape) — boot the
    // active slot instead.
    Slot first = state.active;
    if ((state.pending == Slot::kA || state.pending == Slot::kB) && state.tries_remaining > 0)
        first = state.pending;
    const Slot second = Other(first);

    u64 pos = 0;
    pos = AppendStr(buf, buf_cap, pos,
                    "# DuetOS GRUB configuration — generated from the boot-slot state\n"
                    "# (/boot/duetos-slot.cfg). Regenerated on every slot-state change;\n"
                    "# do not hand-edit.\n"
                    "set timeout=3\n"
                    "set default=");
    if (pos < buf_cap)
        buf[pos++] = static_cast<u8>(EntryIndexChar(first));
    pos = AppendStr(buf, buf_cap, pos, "\nset fallback=\"");
    if (pos < buf_cap)
        buf[pos++] = static_cast<u8>(EntryIndexChar(second));
    pos = AppendStr(buf, buf_cap, pos, " 2\"\n");

    const Slot order[2] = {Slot::kA, Slot::kB};
    for (u32 i = 0; i < 2; ++i)
    {
        const Slot s = order[i];
        pos = AppendStr(buf, buf_cap, pos, "menuentry \"DuetOS (slot ");
        pos = AppendStr(buf, buf_cap, pos, Name(s));
        pos = AppendStr(buf, buf_cap, pos,
                        ")\" {\n"
                        "    insmod part_gpt\n"
                        "    insmod fat\n"
                        "    set root=(hd0,gpt1)\n"
                        "    multiboot2 ");
        pos = AppendStr(buf, buf_cap, pos, SlotKernelPath(s));
        pos = AppendStr(buf, buf_cap, pos, " slot=");
        pos = AppendStr(buf, buf_cap, pos, Name(s));
        pos = AppendStr(buf, buf_cap, pos, "\n    boot\n}\n");
    }
    // Legacy single-kernel entry — the system partition's
    // /boot/duetos-kernel.elf staged by the installer's sentinel
    // step. Last-resort fallback when both slot images are absent.
    // GAP: (hd0,gptN) assumes the install disk enumerates as GRUB's
    // first disk — multi-disk installs need a search-by-UUID line.
    pos = AppendStr(buf, buf_cap, pos,
                    "menuentry \"DuetOS (legacy single-kernel, system partition)\" {\n"
                    "    insmod part_gpt\n"
                    "    insmod fat\n"
                    "    set root=(hd0,gpt2)\n"
                    "    multiboot2 /boot/duetos-kernel.elf\n"
                    "    boot\n}\n");
    return (pos >= buf_cap) ? 0 : pos;
}

bool LoadVia(LoadFn fn, void* ctx, State* out)
{
    if (out == nullptr)
        return false;
    *out = Default();
    out->valid = false;
    if (fn == nullptr)
        return false;
    u8 buf[256];
    const i64 n = fn(ctx, buf, sizeof(buf));
    if (n <= 0)
        return false;
    return Parse(buf, static_cast<u64>(n), out);
}

bool SaveVia(SaveFn fn, void* ctx, const State& state)
{
    if (fn == nullptr || state.active == Slot::kInvalid)
        return false;
    u8 buf[256];
    const u64 n = Serialise(state, buf, sizeof(buf));
    if (n == 0)
        return false;
    return fn(ctx, buf, n);
}

namespace
{

// Substring scan for the self-test's cfg-content assertions.
bool Contains(const u8* hay, u64 hay_len, const char* needle)
{
    u64 needle_len = 0;
    while (needle[needle_len] != '\0')
        ++needle_len;
    if (needle_len == 0 || needle_len > hay_len)
        return false;
    for (u64 i = 0; i + needle_len <= hay_len; ++i)
    {
        u64 j = 0;
        while (j < needle_len && hay[i + j] == static_cast<u8>(needle[j]))
            ++j;
        if (j == needle_len)
            return true;
    }
    return false;
}

} // namespace

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

    // 7. CurrentState defaults; SetCurrentState round-trips; path helpers.
    State cur = CurrentState();
    if (!cur.valid || cur.active != Slot::kA)
        ::duetos::core::Panic("fs/boot_slot", "self-test: CurrentState default wrong");
    SetCurrentState(after_healthy);
    if (CurrentState().active != Slot::kB)
        ::duetos::core::Panic("fs/boot_slot", "self-test: SetCurrentState didn't take");
    const char* path_b = SlotKernelPath(Slot::kB);
    if (path_b == nullptr || path_b[0] != '/' || SlotKernelPath(Slot::kInvalid) != nullptr)
        ::duetos::core::Panic("fs/boot_slot", "self-test: SlotKernelPath wrong");
    // Restore default for any subsequent boot consumer.
    SetCurrentState(Default());

    // 8. LoadVia + SaveVia round-trip via in-memory buffer
    //    callbacks — same shape the real FAT32 / ramfs / DuetFS
    //    integrations will use, exercised with no external FS
    //    dependency.
    struct MemBuf
    {
        u8 bytes[256];
        u64 len;
    };
    MemBuf mem = {};
    SaveFn save_fn = +[](void* c, const u8* b, u64 ln) -> bool
    {
        auto* m = static_cast<MemBuf*>(c);
        if (ln > sizeof(m->bytes))
            return false;
        for (u64 i = 0; i < ln; ++i)
            m->bytes[i] = b[i];
        m->len = ln;
        return true;
    };
    LoadFn load_fn = +[](void* c, u8* b, u64 cap) -> i64
    {
        auto* m = static_cast<MemBuf*>(c);
        const u64 want = (m->len < cap) ? m->len : cap;
        for (u64 i = 0; i < want; ++i)
            b[i] = m->bytes[i];
        return static_cast<i64>(want);
    };
    State to_save = Default();
    to_save.active = Slot::kB;
    to_save.last_healthy = Slot::kA;
    if (!SaveVia(save_fn, &mem, to_save))
        ::duetos::core::Panic("fs/boot_slot", "self-test: SaveVia failed");
    State loaded;
    if (!LoadVia(load_fn, &mem, &loaded) || !loaded.valid)
        ::duetos::core::Panic("fs/boot_slot", "self-test: LoadVia rejected round-trip");
    if (loaded.active != Slot::kB || loaded.last_healthy != Slot::kA)
        ::duetos::core::Panic("fs/boot_slot", "self-test: LoadVia lost fields");

    // 9. GrubCfgGenerate: default tracks pending-else-active, both
    //    slot entries carry their slot= cmdline, invalid input and
    //    undersized buffers are refused.
    u8 cfg[kGrubCfgCapacity];
    const u64 cfg_n = GrubCfgGenerate(Default(), cfg, sizeof(cfg));
    if (cfg_n == 0)
        ::duetos::core::Panic("fs/boot_slot", "self-test: GrubCfgGenerate(Default) returned 0");
    if (!Contains(cfg, cfg_n, "set default=0") || !Contains(cfg, cfg_n, "set fallback=\"1 2\""))
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg default/fallback wrong for Default state");
    if (!Contains(cfg, cfg_n, "/boot/duetos-kernel-a.elf slot=a") ||
        !Contains(cfg, cfg_n, "/boot/duetos-kernel-b.elf slot=b"))
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg slot entries malformed");
    State pending_b = BeginInstall(Default(), Slot::kB);
    const u64 cfg_pb = GrubCfgGenerate(pending_b, cfg, sizeof(cfg));
    if (cfg_pb == 0 || !Contains(cfg, cfg_pb, "set default=1") || !Contains(cfg, cfg_pb, "set fallback=\"0 2\""))
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg default didn't follow pending");
    pending_b.tries_remaining = 0; // exhausted install — boot active again
    const u64 cfg_exhausted = GrubCfgGenerate(pending_b, cfg, sizeof(cfg));
    if (cfg_exhausted == 0 || !Contains(cfg, cfg_exhausted, "set default=0"))
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg default ignored exhausted tries");
    State invalid_active = Default();
    invalid_active.active = Slot::kInvalid;
    if (GrubCfgGenerate(invalid_active, cfg, sizeof(cfg)) != 0)
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg accepted invalid active");
    if (GrubCfgGenerate(Default(), cfg, 64) != 0)
        ::duetos::core::Panic("fs/boot_slot", "self-test: cfg accepted undersized buffer");

    KLOG_INFO("fs/boot_slot", "self-test PASS");
}

} // namespace duetos::fs::boot_slot
