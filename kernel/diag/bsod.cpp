#include "diag/bsod.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_mitigations.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "cpu/percpu.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/kstack.h"
#include "sched/sched.h"
#include "time/tick.h"
#include "util/build_config.h"
#include "util/symbols.h"

namespace duetos::diag
{

namespace
{

// Palette — classic blue panel, white ink, brighter accent strip
// at the top so the "FATAL ERROR" line reads from across the
// room. All values are 0x00RRGGBB; the framebuffer driver drops
// the alpha byte.
constexpr u32 kBgBlue = 0x000A2A6Cu;     // deep blue panel
constexpr u32 kAccentBlue = 0x001E5BC0u; // title strip
constexpr u32 kInkWhite = 0x00FFFFFFu;   // primary text
constexpr u32 kInkPale = 0x00C8D0E0u;    // secondary text (registers, logs)

constexpr u32 kGlyphW = 8;
constexpr u32 kLineH = 12;
constexpr u32 kPanelPad = 32;

// klog tail capture. The DumpLogRingTo API takes a function
// pointer; we route into a fixed-size buffer here and then walk
// it line-by-line for rendering. The buffer is global because
// `BsodRender` runs from panic and a 16 KiB stack frame is more
// than a kernel panic-frame should carry.
constexpr u32 kKlogBufBytes = 8192;
char g_klog_buf[kKlogBufBytes];
u32 g_klog_len;

void KlogSink(const char* s)
{
    if (s == nullptr)
        return;
    while (*s != '\0' && g_klog_len + 1 < kKlogBufBytes)
    {
        g_klog_buf[g_klog_len++] = *s++;
    }
    g_klog_buf[g_klog_len < kKlogBufBytes ? g_klog_len : kKlogBufBytes - 1] = '\0';
}

void DrawStringClamped(u32 x, u32 y, const char* s, u32 max_glyphs, u32 fg, u32 bg)
{
    if (s == nullptr)
        return;
    u32 i = 0;
    while (s[i] != '\0' && i < max_glyphs)
    {
        drivers::video::FramebufferDrawChar(x + i * kGlyphW, y, s[i], fg, bg);
        ++i;
    }
}

u32 DrawString(u32 x, u32 y, const char* s, u32 fg, u32 bg)
{
    if (s == nullptr)
        return 0;
    u32 i = 0;
    while (s[i] != '\0')
    {
        drivers::video::FramebufferDrawChar(x + i * kGlyphW, y, s[i], fg, bg);
        ++i;
    }
    return i;
}

void DrawHex64(u32 x, u32 y, u64 v, u32 fg, u32 bg)
{
    static const char kHex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (u32 i = 0; i < 16; ++i)
    {
        buf[2 + i] = kHex[(v >> ((15 - i) * 4)) & 0xF];
    }
    buf[18] = '\0';
    DrawString(x, y, buf, fg, bg);
}

// Walk g_klog_buf line by line, rendering up to max_lines from
// the TAIL (most recent entries). Returns the y-cursor after
// the last line written.
u32 DrawKlogTail(u32 x, u32 y_top, u32 width_px, u32 max_lines, u32 fg, u32 bg)
{
    // First pass — count newlines so we know where the tail starts.
    if (g_klog_len == 0)
        return y_top;
    u32 nl_count = 0;
    for (u32 i = 0; i < g_klog_len; ++i)
        if (g_klog_buf[i] == '\n')
            ++nl_count;
    // Skip leading lines so the most-recent `max_lines` survive.
    u32 skip_lines = (nl_count > max_lines) ? (nl_count - max_lines) : 0;
    u32 cursor = 0;
    while (skip_lines > 0 && cursor < g_klog_len)
    {
        if (g_klog_buf[cursor] == '\n')
            --skip_lines;
        ++cursor;
    }
    // Second pass — render up to `max_lines` lines, clamped to
    // (width_px / kGlyphW) glyphs each. ANSI escape sequences
    // (ESC '[' ... letter) in klog output get stripped on the
    // fly since the BSOD font path doesn't parse them.
    const u32 max_glyphs = width_px / kGlyphW;
    u32 lines_drawn = 0;
    u32 y = y_top;
    while (cursor < g_klog_len && lines_drawn < max_lines)
    {
        u32 line_glyphs = 0;
        while (cursor < g_klog_len && g_klog_buf[cursor] != '\n')
        {
            const char c = g_klog_buf[cursor++];
            if (c == 0x1B)
            {
                // Skip ESC [ ... <letter>.
                if (cursor < g_klog_len && g_klog_buf[cursor] == '[')
                {
                    ++cursor;
                    while (cursor < g_klog_len)
                    {
                        const char z = g_klog_buf[cursor++];
                        if ((z >= 0x40 && z <= 0x7E))
                            break;
                    }
                }
                continue;
            }
            if (line_glyphs < max_glyphs && c >= 0x20 && c < 0x7F)
            {
                drivers::video::FramebufferDrawChar(x + line_glyphs * kGlyphW, y, c, fg, bg);
                ++line_glyphs;
            }
        }
        if (cursor < g_klog_len && g_klog_buf[cursor] == '\n')
            ++cursor;
        y += kLineH;
        ++lines_drawn;
    }
    return y;
}

// Format `secs` as hh:mm:ss and `millis_remainder` as .mmm,
// returning the next x position. Compact uptime line.
u32 DrawUptime(u32 x, u32 y, u64 ticks, u32 fg, u32 bg)
{
    // 100 Hz tick (time::kTickHz). One tick = 10 ms.
    const u64 total_ms = ticks * (1000 / time::kTickHz);
    const u64 hours = (total_ms / 3600000ULL);
    const u64 mins = (total_ms / 60000ULL) % 60;
    const u64 secs = (total_ms / 1000ULL) % 60;
    const u64 ms = total_ms % 1000ULL;
    char buf[16];
    auto two = [](char* dst, u64 v)
    {
        dst[0] = static_cast<char>('0' + (v / 10) % 10);
        dst[1] = static_cast<char>('0' + v % 10);
    };
    auto three = [](char* dst, u64 v)
    {
        dst[0] = static_cast<char>('0' + (v / 100) % 10);
        dst[1] = static_cast<char>('0' + (v / 10) % 10);
        dst[2] = static_cast<char>('0' + v % 10);
    };
    two(&buf[0], hours);
    buf[2] = ':';
    two(&buf[3], mins);
    buf[5] = ':';
    two(&buf[6], secs);
    buf[8] = '.';
    three(&buf[9], ms);
    buf[12] = '\0';
    DrawString(x, y, buf, fg, bg);
    return x + 12 * kGlyphW;
}

// Print a u32 as decimal, returning the next x position.
u32 DrawDecU32(u32 x, u32 y, u32 v, u32 fg, u32 bg)
{
    char buf[12];
    u32 n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(buf))
        {
            buf[n++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
    }
    buf[n] = '\0';
    for (u32 i = 0; i * 2 + 1 < n; ++i)
    {
        const char t = buf[i];
        buf[i] = buf[n - 1 - i];
        buf[n - 1 - i] = t;
    }
    DrawString(x, y, buf, fg, bg);
    return x + n * kGlyphW;
}

// Mirror of panic.cpp::PlausibleStackPointer — local copy so the
// BSOD has no cross-TU coupling to internal helpers. Walks the
// same "either higher-half kernel or boot-stack low 1 GiB"
// taxonomy used by the serial backtrace. Kernel-stack arena
// guard pages are excluded for the same reason as the panic-side
// helper: blind forward scans (DrawStackTop) would otherwise
// #PF into the guard page just past the slot top and re-enter
// the trap dispatcher as a "kernel stack overflow" — burying
// the original cause.
bool PlausibleStackPointer(u64 addr)
{
    if (addr == 0)
        return false;
    if ((addr & 0x7) != 0)
        return false;
    if (::duetos::mm::IsKernelStackGuardFault(addr))
        return false;
    if (addr >= 0xFFFF800000000000ULL)
        return true;
    if (addr < 0x40000000ULL)
        return true;
    return false;
}

// Walk the RBP chain and render up to `max_frames` return
// addresses with symbol resolution. Each row format:
//   `  #N  0xADDR  [<name>+0xOFF]`
// Returns the y-cursor after the last row written.
u32 DrawBacktrace(u32 x, u32 y_top, u64 rbp, u32 max_frames, u32 fg, u32 bg)
{
    u32 y = y_top;
    DrawString(x, y, "Backtrace:", fg, bg);
    y += kLineH;
    for (u32 depth = 0; depth < max_frames; ++depth)
    {
        if (!PlausibleStackPointer(rbp))
        {
            DrawString(x + 2 * kGlyphW, y, "[end of chain]", fg, bg);
            y += kLineH;
            return y;
        }
        const u64 saved_rbp = *reinterpret_cast<const u64*>(rbp);
        const u64 ret_addr = *reinterpret_cast<const u64*>(rbp + 8);
        DrawString(x + 2 * kGlyphW, y, "#", fg, bg);
        const u32 after_idx = DrawDecU32(x + 3 * kGlyphW, y, depth, fg, bg);
        DrawString(after_idx, y, "  ", fg, bg);
        DrawHex64(after_idx + 2 * kGlyphW, y, ret_addr, fg, bg);
        core::SymbolResolution sr = {};
        if (core::ResolveAddress(ret_addr, &sr) && sr.entry != nullptr)
        {
            const u32 sym_x = after_idx + 2 * kGlyphW + 18 * kGlyphW + 2 * kGlyphW;
            DrawString(sym_x, y, "[", fg, bg);
            const u32 name_chars = DrawString(sym_x + 1 * kGlyphW, y, sr.entry->name, fg, bg);
            DrawString(sym_x + (1 + name_chars) * kGlyphW, y, "+0x", fg, bg);
            static const char kHex[] = "0123456789abcdef";
            char ofs[9];
            u64 v = sr.offset;
            u32 n = 0;
            if (v == 0)
                ofs[n++] = '0';
            else
                while (v > 0 && n < 8)
                {
                    ofs[n++] = kHex[v & 0xF];
                    v >>= 4;
                }
            ofs[n] = '\0';
            for (u32 i = 0; i * 2 + 1 < n; ++i)
            {
                const char t = ofs[i];
                ofs[i] = ofs[n - 1 - i];
                ofs[n - 1 - i] = t;
            }
            DrawString(sym_x + (1 + name_chars + 3) * kGlyphW, y, ofs, fg, bg);
            DrawString(sym_x + (1 + name_chars + 3 + n) * kGlyphW, y, "]", fg, bg);
        }
        y += kLineH;
        if (saved_rbp <= rbp)
        {
            DrawString(x + 2 * kGlyphW, y, "[chain stopped climbing]", fg, bg);
            y += kLineH;
            return y;
        }
        rbp = saved_rbp;
    }
    return y;
}

// Render `<name>+0xOFF`. Returns the x position immediately after
// the trailing offset glyphs so the caller can continue the line.
u32 DrawSymbolOffset(u32 x, u32 y, const core::SymbolResolution& sr, u32 fg, u32 bg)
{
    if (sr.entry == nullptr)
        return x;
    const u32 name_chars = DrawString(x, y, sr.entry->name, fg, bg);
    const u32 after_name = x + name_chars * kGlyphW;
    DrawString(after_name, y, "+0x", fg, bg);
    static const char kHex[] = "0123456789abcdef";
    char ofs[9];
    u64 v = sr.offset;
    u32 n = 0;
    if (v == 0)
        ofs[n++] = '0';
    else
        while (v > 0 && n < 8)
        {
            ofs[n++] = kHex[v & 0xF];
            v >>= 4;
        }
    ofs[n] = '\0';
    for (u32 i = 0; i * 2 + 1 < n; ++i)
    {
        const char t = ofs[i];
        ofs[i] = ofs[n - 1 - i];
        ofs[n - 1 - i] = t;
    }
    DrawString(after_name + 3 * kGlyphW, y, ofs, fg, bg);
    return after_name + (3 + n) * kGlyphW;
}

// Render the RIP line and (if symbol resolves) an indented
// `at <file>:<line>` continuation line. Returns the y-cursor
// after the last line written so the caller can lay subsequent
// rows below.
u32 DrawResolvedRip(u32 x, u32 y, u64 rip, u32 fg, u32 bg)
{
    DrawString(x, y, "RIP ", fg, bg);
    DrawHex64(x + 4 * kGlyphW, y, rip, fg, bg);
    core::SymbolResolution sr = {};
    if (!core::ResolveAddress(rip, &sr) || sr.entry == nullptr)
    {
        return y + kLineH;
    }
    const u32 sym_x = x + 4 * kGlyphW + 18 * kGlyphW + 2 * kGlyphW;
    DrawString(sym_x, y, "[", fg, bg);
    const u32 after_sym = DrawSymbolOffset(sym_x + 1 * kGlyphW, y, sr, fg, bg);
    DrawString(after_sym, y, "]", fg, bg);
    y += kLineH;
    if (sr.entry->file != nullptr && sr.entry->file[0] != '\0' && sr.entry->file[0] != '?')
    {
        DrawString(x + 4 * kGlyphW, y, "at ", kInkPale, bg);
        const u32 file_chars = DrawString(x + 7 * kGlyphW, y, sr.entry->file, kInkPale, bg);
        const u32 after_file = x + (7 + file_chars) * kGlyphW;
        DrawString(after_file, y, ":", kInkPale, bg);
        (void)DrawDecU32(after_file + 1 * kGlyphW, y, sr.entry->line, kInkPale, bg);
        y += kLineH;
    }
    return y;
}

// One-line CPU mitigation summary. Each token is "name=on/off".
// The condensed format trades self-documenting prose for a single
// row of grep-friendly tokens — when a crash is silicon-state
// related (Meltdown / Spectre fired, SMEP didn't block what it
// should have), the operator wants every flag visible at once.
u32 DrawMitigationsLine(u32 x, u32 y, u32 fg, u32 bg)
{
    DrawString(x, y, "Mitigations: ", fg, bg);
    u32 cx = x + 13 * kGlyphW;
    const u64 cr4 = arch::ReadCr4();
    const bool smep_on = (cr4 & (1ULL << 20)) != 0;
    const bool smap_on = (cr4 & (1ULL << 21)) != 0;
    const bool umip_on = (cr4 & (1ULL << 11)) != 0;
    const bool nx_on = (arch::ReadCr0() & 0); // CR0 doesn't hold NX; just a placeholder until EFER read lands.
    (void)nx_on;
    const auto& m = arch::CpuMitigationsGet();
    auto tok = [&](const char* label, bool on)
    {
        const u32 lc = DrawString(cx, y, label, fg, bg);
        cx += lc * kGlyphW;
        DrawString(cx, y, "=", fg, bg);
        cx += kGlyphW;
        DrawString(cx, y, on ? "on" : "off", on ? fg : kInkPale, bg);
        cx += (on ? 2u : 3u) * kGlyphW;
        DrawString(cx, y, "  ", fg, bg);
        cx += 2 * kGlyphW;
    };
    tok("smep", smep_on);
    tok("smap", smap_on);
    tok("umip", umip_on);
    tok("ibrs", m.has_ibrs);
    tok("eibrs", m.has_eibrs);
    tok("stibp", m.has_stibp);
    tok("retpoline", m.needs_retpolines);
    return y + kLineH;
}

// Memory + free-frame snapshot. Heap is a single 2 MiB pool today
// so used/free reads in KiB.
u32 DrawMemoryLine(u32 x, u32 y, u32 fg, u32 bg)
{
    const mm::KernelHeapStats h = mm::KernelHeapStatsRead();
    const u64 free_frames = mm::FreeFramesCount();
    DrawString(x, y, "Memory:    ", fg, bg);
    u32 cx = x + 11 * kGlyphW;
    DrawString(cx, y, "heap_used=", fg, bg);
    cx += 10 * kGlyphW;
    cx = DrawDecU32(cx, y, static_cast<u32>(h.used_bytes / 1024), fg, bg);
    DrawString(cx, y, "K  free=", fg, bg);
    cx += 8 * kGlyphW;
    cx = DrawDecU32(cx, y, static_cast<u32>(h.free_bytes / 1024), fg, bg);
    DrawString(cx, y, "K  frag=", fg, bg);
    cx += 8 * kGlyphW;
    cx = DrawDecU32(cx, y, static_cast<u32>(h.free_chunk_count), fg, bg);
    DrawString(cx, y, "  frames_free=", fg, bg);
    cx += 14 * kGlyphW;
    cx = DrawDecU32(cx, y, static_cast<u32>(free_frames), fg, bg);
    return y + kLineH;
}

// Fault-counter snapshot. Six 64-bit counters compressed into one
// row: A=access-violation, NX=nx-violation, W=write-to-ro,
// SO=stack-overflow, R=reserved-bit, GP=#GP, UD=#UD. If a counter
// is zero we still render it so the row layout stays constant
// (the eye reads the SAME column for the same value).
u32 DrawFaultLine(u32 x, u32 y, u32 fg, u32 bg)
{
    const arch::FaultCounts f = arch::FaultCountsSnapshot();
    DrawString(x, y, "Faults:    ", fg, bg);
    u32 cx = x + 11 * kGlyphW;
    auto col = [&](const char* label, u64 v)
    {
        const u32 lc = DrawString(cx, y, label, fg, bg);
        cx += lc * kGlyphW;
        DrawString(cx, y, "=", fg, bg);
        cx += kGlyphW;
        cx = DrawDecU32(cx, y, static_cast<u32>(v), fg, bg);
        DrawString(cx, y, "  ", fg, bg);
        cx += 2 * kGlyphW;
    };
    col("AV", f.access_violation);
    col("NX", f.nx_violation);
    col("W", f.write_to_ro);
    col("SO", f.stack_overflow);
    col("RES", f.reserved_bit);
    col("GP", f.gp);
    col("UD", f.ud);
    return y + kLineH;
}

// Held-locks snapshot for the panicking CPU. If lockdep didn't
// record anything (cap=0), the section is skipped entirely so
// the layout doesn't leak empty rows. Each row format:
//   `  [N] 0xADDR acq@ <symbol+0xOFF>`
// Innermost (most-recently-acquired) first.
u32 DrawHeldLocks(u32 x, u32 y_top, u32 fg, u32 bg)
{
    if (!cpu::BspInstalled())
        return y_top;
    const cpu::PerCpu* p = cpu::CurrentCpu();
    if (p == nullptr || p->held_locks_count == 0)
        return y_top;
    u32 y = y_top;
    DrawString(x, y, "Held locks (", fg, bg);
    u32 cx = x + 12 * kGlyphW;
    cx = DrawDecU32(cx, y, p->held_locks_count, fg, bg);
    DrawString(cx, y, ", innermost first):", fg, bg);
    y += kLineH;
    const u32 cap = (p->held_locks_count < cpu::kPerCpuMaxHeldLocks) ? p->held_locks_count : cpu::kPerCpuMaxHeldLocks;
    for (u32 i = 0; i < cap; ++i)
    {
        const u32 idx = cap - 1 - i;
        DrawString(x + 2 * kGlyphW, y, "[", fg, bg);
        const u32 after_idx = DrawDecU32(x + 3 * kGlyphW, y, idx, fg, bg);
        DrawString(after_idx, y, "] ", fg, bg);
        const u32 hex_x = after_idx + 2 * kGlyphW;
        DrawHex64(hex_x, y, reinterpret_cast<u64>(p->held_locks[idx]), fg, bg);
        const u32 after_hex = hex_x + 18 * kGlyphW;
        DrawString(after_hex, y, "  acq@ ", fg, bg);
        const u32 sym_x = after_hex + 7 * kGlyphW;
        core::SymbolResolution sr = {};
        if (core::ResolveAddress(p->held_lock_rips[idx], &sr) && sr.entry != nullptr)
            (void)DrawSymbolOffset(sym_x, y, sr, fg, bg);
        else
            DrawHex64(sym_x, y, p->held_lock_rips[idx], fg, bg);
        y += kLineH;
    }
    return y;
}

// Hex dump of `quads` 64-bit values starting at `rsp`. Renders 2
// quads per row (32 chars of hex + spacing), so 8 quads = 4 rows
// = ~48 px of vertical space. Each deref is guarded by
// PlausibleStackPointer so a corrupt RSP can't fault-during-
// panic.
u32 DrawStackTop(u32 x, u32 y_top, u64 rsp, u32 quads, u32 fg, u32 bg)
{
    DrawString(x, y_top, "Stack top (", fg, bg);
    u32 cx = x + 11 * kGlyphW;
    cx = DrawDecU32(cx, y_top, quads, fg, bg);
    DrawString(cx, y_top, " qwords @ RSP):", fg, bg);
    u32 y = y_top + kLineH;
    // Layout per row: "  +NN  <hex0>    <hex1>". `+NN` is the
    // decimal byte offset from RSP (0, 8, 16, ...). Each hex
    // value is 18 chars; we put the second column at a fixed
    // 22-char gap so the columns don't touch.
    for (u32 i = 0; i < quads; ++i)
    {
        if ((i & 1) == 0)
        {
            DrawString(x + 2 * kGlyphW, y, "+", fg, bg);
            (void)DrawDecU32(x + 3 * kGlyphW, y, i * 8, fg, bg);
        }
        const u32 col = (i & 1) ? (x + 38 * kGlyphW) : (x + 8 * kGlyphW);
        const u64 addr = rsp + i * 8;
        if (PlausibleStackPointer(addr))
        {
            const u64 v = *reinterpret_cast<const u64*>(addr);
            DrawHex64(col, y, v, fg, bg);
        }
        else
        {
            DrawString(col, y, "<unreadable>", fg, bg);
        }
        if (i & 1)
            y += kLineH;
    }
    if (quads & 1)
        y += kLineH;
    return y;
}

bool Read8042Byte(u8& out)
{
    // Status port 0x64; output buffer full is bit 0. Mouse data
    // is bit 5 — skip those (the BSOD doesn't care about mouse
    // events while waiting for a reboot key).
    const u8 status = arch::Inb(0x64);
    if ((status & 0x01) == 0)
        return false;
    if ((status & 0x20) != 0)
    {
        (void)arch::Inb(0x60);
        return false;
    }
    out = arch::Inb(0x60);
    return true;
}

[[noreturn]] void WaitForKeyAndReset()
{
    // Poll the 8042 status port forever. We don't have IRQs
    // (CLI was held by the panic path; even if STI were issued,
    // re-entering the keyboard ISR from a panicked kernel would
    // be a worse outcome than this polling loop). Once any
    // keypress arrives, write 0xFE to port 0x64 to issue a
    // controller reset — every BIOS / UEFI / virtual board the
    // framebuffer console supports respects it.
    for (;;)
    {
        u8 byte = 0;
        if (Read8042Byte(byte))
        {
            // Break-codes (high bit set) are key releases; ignore
            // them so the user doesn't get a reset on the
            // release of the key they were already holding when
            // we entered the BSOD.
            if ((byte & 0x80) == 0)
            {
                arch::SerialWrite("[bsod] key received — issuing 8042 reset\n");
                arch::Outb(0x64, 0xFE);
                // The reset takes a few microseconds. Spin
                // through HLT in case it doesn't arrive.
                for (;;)
                {
                    asm volatile("hlt");
                }
            }
        }
        asm volatile("pause" ::: "memory");
    }
}

} // namespace

void BsodRender(const char* subsystem, const char* message, duetos::u64 rip, duetos::u64 rsp, duetos::u64 rbp,
                duetos::u64 value, bool has_value)
{
    if (!drivers::video::FramebufferAvailable())
    {
        // No video — caller will just halt. The serial dump
        // already covers diagnostics for headless boots.
        return;
    }

    // Disable interrupts before painting. The timer IRQ would
    // otherwise wake the ui-ticker, which calls DesktopCompose
    // and overwrites the BSOD with the live desktop. Once CLI
    // is set, our polling-mode 8042 read stays the only way out
    // of this CPU until reset fires — and reset is a port-out
    // write, not IRQ-driven, so disabling interrupts is safe.
    asm volatile("cli" ::: "memory");

    drivers::video::FramebufferInfo fb = drivers::video::FramebufferGet();
    const u32 W = fb.width;
    const u32 H = fb.height;

    drivers::video::FramebufferFillRect(0, 0, W, H, kBgBlue);

    // Title strip.
    drivers::video::FramebufferFillRect(0, 0, W, 40, kAccentBlue);
    DrawString(kPanelPad, 14, "DUETOS - A FATAL ERROR OCCURRED", kInkWhite, kAccentBlue);

    u32 y = 48;

    // Identity block.
    DrawString(kPanelPad, y, "Subsystem: ", kInkWhite, kBgBlue);
    DrawStringClamped(kPanelPad + 11 * kGlyphW, y, (subsystem != nullptr) ? subsystem : "?",
                      (W - 2 * kPanelPad) / kGlyphW - 11, kInkWhite, kBgBlue);
    y += kLineH;
    DrawString(kPanelPad, y, "Message:   ", kInkWhite, kBgBlue);
    DrawStringClamped(kPanelPad + 11 * kGlyphW, y, (message != nullptr) ? message : "?",
                      (W - 2 * kPanelPad) / kGlyphW - 11, kInkWhite, kBgBlue);
    y += kLineH;
    if (has_value)
    {
        DrawString(kPanelPad, y, "Value:     ", kInkPale, kBgBlue);
        DrawHex64(kPanelPad + 11 * kGlyphW, y, value, kInkPale, kBgBlue);
        y += kLineH;
    }

    // Build + uptime + CPU + task line. Compact "what binary, when,
    // where" block — invaluable for operators triaging a field crash.
    y += kLineH / 2;
    DrawString(kPanelPad, y, "Build:     ", kInkPale, kBgBlue);
    const char* flavor = core::BuildFlavorName();
    const u32 after_flavor =
        kPanelPad + 11 * kGlyphW + DrawString(kPanelPad + 11 * kGlyphW, y, flavor, kInkPale, kBgBlue) * kGlyphW;
    DrawString(after_flavor, y, " ", kInkPale, kBgBlue);
    const u32 hash_chars = DrawString(after_flavor + 1 * kGlyphW, y, core::BuildGitHash(), kInkPale, kBgBlue);
    const u32 after_hash = after_flavor + (1 + hash_chars) * kGlyphW;
    DrawString(after_hash, y, " ", kInkPale, kBgBlue);
    DrawString(after_hash + 1 * kGlyphW, y, core::BuildDate(), kInkPale, kBgBlue);
    y += kLineH;

    DrawString(kPanelPad, y, "Uptime:    ", kInkPale, kBgBlue);
    const u64 ticks = sched::SchedNowTicks();
    const u32 after_up = DrawUptime(kPanelPad + 11 * kGlyphW, y, ticks, kInkPale, kBgBlue);
    DrawString(after_up + 2 * kGlyphW, y, "CPU ", kInkPale, kBgBlue);
    const u32 after_cpu_label = after_up + 6 * kGlyphW;
    const u32 after_cpu = DrawDecU32(after_cpu_label, y, cpu::CurrentCpuIdOrBsp(), kInkPale, kBgBlue);
    DrawString(after_cpu + 2 * kGlyphW, y, "Task ", kInkPale, kBgBlue);
    const char* task_name = sched::TaskName(sched::CurrentTask());
    DrawStringClamped(after_cpu + 7 * kGlyphW, y, (task_name != nullptr) ? task_name : "?",
                      (W - 2 * kPanelPad) / kGlyphW - ((after_cpu + 7 * kGlyphW - kPanelPad) / kGlyphW), kInkPale,
                      kBgBlue);
    y += kLineH * 2;

    // Register block.
    y = DrawResolvedRip(kPanelPad, y, rip, kInkWhite, kBgBlue);
    DrawString(kPanelPad, y, "RSP ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW, y, rsp, kInkPale, kBgBlue);
    DrawString(kPanelPad + 4 * kGlyphW + 19 * kGlyphW, y, "  RBP ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW, y, rbp, kInkPale, kBgBlue);
    y += kLineH;
    // Control registers — CR2 is the faulting linear address for
    // page faults, CR3 is the active address space (which process),
    // CR4 holds SMEP/SMAP/CET enable bits. Reading them is safe
    // here even though Panic was called from arbitrary context —
    // CR-register reads have no side effects.
    DrawString(kPanelPad, y, "CR2 ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW, y, arch::ReadCr2(), kInkPale, kBgBlue);
    DrawString(kPanelPad + 4 * kGlyphW + 19 * kGlyphW, y, "  CR3 ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW, y, arch::ReadCr3(), kInkPale, kBgBlue);
    DrawString(kPanelPad + 4 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW + 19 * kGlyphW, y, "  CR4 ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW, y, arch::ReadCr4(),
              kInkPale, kBgBlue);
    y += kLineH;
    y = DrawMitigationsLine(kPanelPad, y, kInkPale, kBgBlue);
    y = DrawMemoryLine(kPanelPad, y, kInkPale, kBgBlue);
    y = DrawFaultLine(kPanelPad, y, kInkPale, kBgBlue);
    y += kLineH;

    // Backtrace — walk RBP chain. Up to 6 frames.
    y = DrawBacktrace(kPanelPad, y, rbp, /*max_frames=*/6, kInkWhite, kBgBlue);
    y += kLineH / 2;

    // Held locks — usually empty; only renders rows when something
    // was actually held at panic. Critical for deadlock triage.
    const u32 y_before_locks = y;
    y = DrawHeldLocks(kPanelPad, y, kInkPale, kBgBlue);
    if (y > y_before_locks)
        y += kLineH / 2;

    // Stack-top hex dump — 8 quads = ~64 bytes of stack, enough
    // to see the immediate frame's locals + the caller's saved
    // RBP + return addr.
    y = DrawStackTop(kPanelPad, y, rsp, /*quads=*/8, kInkPale, kBgBlue);
    y += kLineH / 2;

    // klog tail — capture ring through sink, render last 10 lines.
    DrawString(kPanelPad, y, "Recent kernel log:", kInkWhite, kBgBlue);
    y += kLineH;
    g_klog_len = 0;
    core::DumpLogRingTo(&KlogSink);
    (void)DrawKlogTail(kPanelPad, y, W - 2 * kPanelPad, /*max_lines=*/10, kInkPale, kBgBlue);

    // Footer strip.
    const u32 footer_y = (H > 40) ? (H - 40) : 0;
    drivers::video::FramebufferFillRect(0, footer_y, W, 40, kAccentBlue);
    DrawString(kPanelPad, footer_y + 14, "PRESS ANY KEY TO REBOOT (the kernel will issue 8042 reset)", kInkWhite,
               kAccentBlue);

    drivers::video::FramebufferPresent();

    arch::SerialWrite("[bsod] rendered — waiting for keypress to reboot\n");
    WaitForKeyAndReset();
}

} // namespace duetos::diag
