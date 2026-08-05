// test_kernel32_console_vt.cpp — hosted unit test for the VT-sequence
// tracker that keeps the kernel32 console screen-buffer mirror
// (cursor + Win32 attribute word) coherent while WriteConsole bytes
// pass through to the downstream VT terminal under
// ENABLE_VIRTUAL_TERMINAL_PROCESSING.
//
// Covers: userland/libs/kernel32/kernel32_console_vt.h
//   (duetos_cvt_feed state machine: CSI cursor movement + CUP, SGR
//    colour mapping into the Win32 attribute word, ground-state
//    controls, printable advance/wrap, split feeds, private and
//    unknown sequences).

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/kernel32_console_vt.h"

#include <cstring>

namespace
{

duetos_cvt_state fresh()
{
    duetos_cvt_state st;
    duetos_cvt_init(&st, 80, 25, 0x07);
    return st;
}

void feed(duetos_cvt_state* st, const char* s)
{
    duetos_cvt_feed(st, reinterpret_cast<const unsigned char*>(s), static_cast<unsigned>(std::strlen(s)));
}

} // namespace

int main()
{
    // Printable advance and wrap at the right edge.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "abc");
        EXPECT_EQ(st.cur_x, 3);
        EXPECT_EQ(st.cur_y, 0);
        for (int i = 0; i < 100; ++i)
            feed(&st, "x");
        // Deferred wrap (kernel Terminal semantics): the cursor sits
        // at x==80 after filling row 0 (77 more glyphs), the 78th
        // extra glyph wraps to (1,1), and the last 22 land at x=23.
        EXPECT_EQ(st.cur_y, 1);
        EXPECT_EQ(st.cur_x, 23);
    }

    // Ground-state controls: CR, LF, BS, TAB.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "hello\r");
        EXPECT_EQ(st.cur_x, 0);
        EXPECT_EQ(st.cur_y, 0);
        feed(&st, "hi\n");
        EXPECT_EQ(st.cur_x, 0); // LF is a newline: x=0, y+1
        EXPECT_EQ(st.cur_y, 1);
        feed(&st, "ab\b");
        EXPECT_EQ(st.cur_x, 1);
        feed(&st, "\b\b"); // BS never wraps to the previous row
        EXPECT_EQ(st.cur_x, 0);
        EXPECT_EQ(st.cur_y, 1);
        feed(&st, "\t");
        EXPECT_EQ(st.cur_x, 8); // next 8-column stop
        feed(&st, "x\t");
        EXPECT_EQ(st.cur_x, 16);
    }

    // LF pins y at the bottom row (the sink scrolls; the mirror clamps).
    {
        duetos_cvt_state st = fresh();
        for (int i = 0; i < 30; ++i)
            feed(&st, "\n");
        EXPECT_EQ(st.cur_y, 24);
    }

    // CUP: 1-based row;col, clamped; bare ESC[H homes.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[10;20H");
        EXPECT_EQ(st.cur_y, 9);
        EXPECT_EQ(st.cur_x, 19);
        feed(&st, "\x1b[H");
        EXPECT_EQ(st.cur_y, 0);
        EXPECT_EQ(st.cur_x, 0);
        feed(&st, "\x1b[999;999H"); // clamp to the screen box
        EXPECT_EQ(st.cur_y, 24);
        EXPECT_EQ(st.cur_x, 79);
        feed(&st, "\x1b[5;7f"); // HVP alias
        EXPECT_EQ(st.cur_y, 4);
        EXPECT_EQ(st.cur_x, 6);
        feed(&st, "\x1b[;30H"); // empty row param defaults to 1
        EXPECT_EQ(st.cur_y, 0);
        EXPECT_EQ(st.cur_x, 29);
    }

    // Relative movement with clamps; missing/zero param means 1.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[12;40H");
        feed(&st, "\x1b[3A");
        EXPECT_EQ(st.cur_y, 8);
        feed(&st, "\x1b[B");
        EXPECT_EQ(st.cur_y, 9);
        feed(&st, "\x1b[0B"); // 0 -> default 1
        EXPECT_EQ(st.cur_y, 10);
        feed(&st, "\x1b[5C");
        EXPECT_EQ(st.cur_x, 44);
        feed(&st, "\x1b[100C"); // clamp right
        EXPECT_EQ(st.cur_x, 79);
        feed(&st, "\x1b[200D"); // clamp left
        EXPECT_EQ(st.cur_x, 0);
        feed(&st, "\x1b[99A"); // clamp top
        EXPECT_EQ(st.cur_y, 0);
    }

    // ED / EL: erase changes the downstream grid, not the mirror.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[12;40H\x1b[2J\x1b[K");
        EXPECT_EQ(st.cur_y, 11);
        EXPECT_EQ(st.cur_x, 39);
    }

    // SGR: ANSI colour indices map into the Win32 attribute word
    // with the R/B bit swap; bold is FOREGROUND_INTENSITY.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[31m"); // red fg -> FOREGROUND_RED (0x04)
        EXPECT_EQ(st.attrs, (unsigned short)0x04);
        feed(&st, "\x1b[1m"); // bold adds intensity
        EXPECT_EQ(st.attrs, (unsigned short)0x0C);
        feed(&st, "\x1b[44m"); // blue bg -> BACKGROUND_BLUE (0x10)
        EXPECT_EQ(st.attrs, (unsigned short)0x1C);
        feed(&st, "\x1b[0m"); // reset
        EXPECT_EQ(st.attrs, (unsigned short)0x07);
        feed(&st, "\x1b[1;33m"); // bold yellow = red|green|intensity
        EXPECT_EQ(st.attrs, (unsigned short)0x0E);
        feed(&st, "\x1b[22m"); // bold off, colour kept
        EXPECT_EQ(st.attrs, (unsigned short)0x06);
        feed(&st, "\x1b[m"); // bare SGR resets
        EXPECT_EQ(st.attrs, (unsigned short)0x07);
        feed(&st, "\x1b[96m"); // bright cyan fg = green|blue|intensity
        EXPECT_EQ(st.attrs, (unsigned short)0x0B);
        feed(&st, "\x1b[101m"); // bright red bg
        EXPECT_EQ(st.attrs, (unsigned short)0xCB);
        feed(&st, "\x1b[39;49m"); // default fg + bg
        EXPECT_EQ(st.attrs, (unsigned short)0x0F);
        feed(&st, "\x1b[37;40m"); // white on black
        EXPECT_EQ(st.attrs, (unsigned short)0x0F);
        feed(&st, "\x1b[30;47m"); // black on white
        EXPECT_EQ(st.attrs, (unsigned short)0x78);
    }

    // 256-colour / truecolour selectors are consumed without
    // corrupting later parameters.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[38;5;196;44m"); // ext fg skipped, blue bg applies
        EXPECT_EQ(st.attrs, (unsigned short)0x17);
        feed(&st, "\x1b[0m\x1b[48;2;10;20;30;31m");
        EXPECT_EQ(st.attrs, (unsigned short)0x04);
    }

    // A sequence split across feed calls keeps parser state.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b");
        feed(&st, "[");
        feed(&st, "1");
        feed(&st, "0;2");
        feed(&st, "0H");
        EXPECT_EQ(st.cur_y, 9);
        EXPECT_EQ(st.cur_x, 19);
    }

    // Private sequences (ESC[?25l) and unknown finals change nothing.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[5;5H");
        feed(&st, "\x1b[?25l\x1b[?1049h\x1b[3g");
        EXPECT_EQ(st.cur_y, 4);
        EXPECT_EQ(st.cur_x, 4);
        EXPECT_EQ(st.attrs, (unsigned short)0x07);
        feed(&st, "x"); // parser is back in ground state
        EXPECT_EQ(st.cur_x, 5);
    }

    // Non-CSI escape drops the introducer and returns to ground.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b(Bab");
        EXPECT_EQ(st.cur_x, 3); // 'B' prints after the dropped '(' GAP
    }

    // Oversized parameter values clamp instead of overflowing.
    {
        duetos_cvt_state st = fresh();
        feed(&st, "\x1b[123456789C");
        EXPECT_EQ(st.cur_x, 79);
    }

    return duetos_host_test::finish_main("kernel32_console_vt");
}
