#include "diag/bsod.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"
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
constexpr u32 kGlyphH = 8;
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

void DrawResolvedRip(u32 x, u32 y, u64 rip, u32 fg, u32 bg)
{
    DrawString(x, y, "RIP ", fg, bg);
    DrawHex64(x + 4 * kGlyphW, y, rip, fg, bg);
    core::SymbolResolution sr = {};
    if (core::ResolveAddress(rip, &sr) && sr.entry != nullptr)
    {
        const u32 sym_x = x + 4 * kGlyphW + 18 * kGlyphW + kGlyphW;
        DrawString(sym_x, y, "  ", fg, bg);
        const u32 name_chars = DrawString(sym_x + 2 * kGlyphW, y, sr.entry->name, fg, bg);
        const u32 plus_x = sym_x + (2 + name_chars) * kGlyphW;
        DrawString(plus_x, y, "+0x", fg, bg);
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
        DrawString(plus_x + 3 * kGlyphW, y, ofs, fg, bg);
    }
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

    drivers::video::FramebufferInfo fb = drivers::video::FramebufferGet();
    const u32 W = fb.width;
    const u32 H = fb.height;

    // 1. Wipe to deep blue.
    drivers::video::FramebufferFillRect(0, 0, W, H, kBgBlue);

    // 2. Accent strip — top 48 px, brighter blue, holds the
    //    title in slightly-large bitmap caps.
    drivers::video::FramebufferFillRect(0, 0, W, 48, kAccentBlue);
    DrawString(kPanelPad, 16, "DUETOS - A FATAL ERROR OCCURRED", kInkWhite, kAccentBlue);

    u32 y = 48 + kPanelPad;

    DrawString(kPanelPad, y, "Subsystem: ", kInkWhite, kBgBlue);
    DrawString(kPanelPad + 11 * kGlyphW, y, (subsystem != nullptr) ? subsystem : "?", kInkWhite, kBgBlue);
    y += kLineH;
    DrawString(kPanelPad, y, "Message:   ", kInkWhite, kBgBlue);
    DrawStringClamped(kPanelPad + 11 * kGlyphW, y, (message != nullptr) ? message : "?",
                      (W - 2 * kPanelPad) / kGlyphW - 11, kInkWhite, kBgBlue);
    y += kLineH;
    if (has_value)
    {
        DrawString(kPanelPad, y, "Value:     ", kInkWhite, kBgBlue);
        DrawHex64(kPanelPad + 11 * kGlyphW, y, value, kInkWhite, kBgBlue);
        y += kLineH;
    }

    y += kLineH;
    DrawResolvedRip(kPanelPad, y, rip, kInkWhite, kBgBlue);
    y += kLineH;
    DrawString(kPanelPad, y, "RSP ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW, y, rsp, kInkPale, kBgBlue);
    DrawString(kPanelPad + 4 * kGlyphW + 19 * kGlyphW, y, "  RBP ", kInkPale, kBgBlue);
    DrawHex64(kPanelPad + 4 * kGlyphW + 19 * kGlyphW + 6 * kGlyphW, y, rbp, kInkPale, kBgBlue);
    y += kLineH * 2;

    // 3. klog tail — capture the ring through our sink, then walk
    //    the captured buffer for rendering. We capture AFTER the
    //    panic header is on screen so the user sees the
    //    high-priority lines even if klog capture goes wrong.
    DrawString(kPanelPad, y, "Recent kernel log:", kInkWhite, kBgBlue);
    y += kLineH;
    g_klog_len = 0;
    core::DumpLogRingTo(&KlogSink);
    const u32 klog_y = DrawKlogTail(kPanelPad, y, W - 2 * kPanelPad, 20, kInkPale, kBgBlue);
    (void)klog_y;

    // 4. Footer — instructions at the bottom of the panel,
    //    same accent colour as the title strip so it visually
    //    bookends the message.
    const u32 footer_y = (H > 48) ? (H - 48) : 0;
    drivers::video::FramebufferFillRect(0, footer_y, W, 48, kAccentBlue);
    DrawString(kPanelPad, footer_y + 16, "PRESS ANY KEY TO REBOOT (the kernel will issue 8042 reset)", kInkWhite,
               kAccentBlue);

    drivers::video::FramebufferPresent();

    arch::SerialWrite("[bsod] rendered — waiting for keypress to reboot\n");
    WaitForKeyAndReset();
}

} // namespace duetos::diag
