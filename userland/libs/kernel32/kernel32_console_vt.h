/*
 * userland/libs/kernel32/kernel32_console_vt.h
 *
 * Freestanding VT-sequence *tracker* for the kernel32 console
 * screen-buffer mirror. This is deliberately NOT a renderer and NOT
 * a second copy of the kernel's VT parser: glyph rendering and
 * erase semantics live downstream in the one VT-interpreting sink
 * (the windowed Terminal app via kernel/util/vt_parser, or the host
 * serial terminal). DuetOS's Win32 console model is "the console IS
 * a VT terminal": WriteConsole bytes pass through to that sink
 * unmodified. What kernel32 must keep on its side is the
 * CONSOLE_SCREEN_BUFFER_INFO mirror — cursor position and the
 * Win32 attribute word — so GetConsoleScreenBufferInfo stays
 * coherent after an app drives the cursor/colours with VT
 * sequences under ENABLE_VIRTUAL_TERMINAL_PROCESSING.
 *
 * The state machine mirrors the clamp semantics of the kernel
 * Terminal (kernel/apps/terminal.cpp OnCsi/OnExecute): missing or
 * zero CSI parameters default per xterm, cursor moves clamp to the
 * screen box, LF is newline (x=0, y+1) with scroll pinning y at the
 * bottom row, BS never wraps to the previous row.
 *
 * Tracked: CSI CUU/CUD/CUF/CUB ('A'..'D'), CUP/HVP ('H'/'f'), SGR
 * ('m': 0/1/22, 30-37/39, 40-47/49, 90-97, 100-107, 38/48 extended
 * selectors are consumed but unmapped), plus ground-state controls
 * BS/HT/CR/LF/VT/FF and printable-advance with wrap. ED/EL ('J' /
 * 'K') are accepted and change nothing here — erase mutates cell
 * contents, which live in the downstream terminal grid, not in the
 * SBI mirror.
 *
 * Hosted unit test: tests/host/test_kernel32_console_vt.cpp.
 */
#pragma once

enum
{
    DUETOS_CVT_MAX_PARAMS = 8
};

/* Parse states. */
enum
{
    DUETOS_CVT_GROUND = 0,
    DUETOS_CVT_ESCAPE = 1,
    DUETOS_CVT_CSI = 2
};

typedef struct duetos_cvt_state
{
    short cols, rows;      /* screen geometry (80x25) */
    short cur_x, cur_y;    /* 0-based cursor mirror */
    unsigned short attrs;  /* Win32 attribute word mirror */
    unsigned char pstate;  /* DUETOS_CVT_* parse state */
    unsigned char nparams; /* completed (';'-terminated) params */
    unsigned char have_digit;
    unsigned char priv; /* private marker seen ('?', '<', ...) */
    unsigned short params[DUETOS_CVT_MAX_PARAMS];
} duetos_cvt_state;

static inline void duetos_cvt_init(duetos_cvt_state* st, short cols, short rows, unsigned short attrs)
{
    st->cols = cols;
    st->rows = rows;
    st->cur_x = 0;
    st->cur_y = 0;
    st->attrs = attrs;
    st->pstate = DUETOS_CVT_GROUND;
    st->nparams = 0;
    st->have_digit = 0;
    st->priv = 0;
    for (int i = 0; i < DUETOS_CVT_MAX_PARAMS; ++i)
        st->params[i] = 0;
}

static inline void duetos_cvt_seq_reset(duetos_cvt_state* st)
{
    st->pstate = DUETOS_CVT_GROUND;
    st->nparams = 0;
    st->have_digit = 0;
    st->priv = 0;
    for (int i = 0; i < DUETOS_CVT_MAX_PARAMS; ++i)
        st->params[i] = 0;
}

/* "Missing or 0 means default" — matches ParamOr in the kernel
 * Terminal and xterm's convention for cursor-movement codes. */
static inline unsigned duetos_cvt_param_or(const duetos_cvt_state* st, unsigned count, unsigned idx, unsigned def_val)
{
    if (idx >= count)
        return def_val;
    return (st->params[idx] == 0) ? def_val : st->params[idx];
}

/* ANSI 3-bit colour index (bit0=R, bit1=G, bit2=B) to the Win32
 * attribute nibble (bit0=B, bit1=G, bit2=R): swap bits 0 and 2. */
static inline unsigned short duetos_cvt_ansi_to_win3(unsigned short idx)
{
    const unsigned short r = idx & 1;
    const unsigned short g = (idx >> 1) & 1;
    const unsigned short b = (idx >> 2) & 1;
    return (unsigned short)((r << 2) | (g << 1) | b);
}

static inline void duetos_cvt_apply_sgr(duetos_cvt_state* st, unsigned count)
{
    if (count == 0)
    {
        st->attrs = 0x07; /* bare ESC[m resets, matching xterm */
        return;
    }
    unsigned i = 0;
    while (i < count)
    {
        const unsigned short p = st->params[i];
        if (p == 38 || p == 48)
        {
            /* Extended-colour selector: consume 38;5;N / 38;2;R;G;B.
             * Not representable in the 4-bit attribute word — skip.
             * Malformed selector ends processing (kernel Terminal
             * does the same). */
            if (i + 1 < count && st->params[i + 1] == 5 && i + 2 < count)
            {
                i += 3;
                continue;
            }
            if (i + 1 < count && st->params[i + 1] == 2 && i + 4 < count)
            {
                i += 5;
                continue;
            }
            break;
        }
        if (p == 0)
            st->attrs = 0x07;
        else if (p == 1)
            st->attrs |= 0x08; /* bold -> FOREGROUND_INTENSITY */
        else if (p == 22)
            st->attrs = (unsigned short)(st->attrs & ~0x08u);
        else if (p >= 30 && p <= 37)
            st->attrs = (unsigned short)((st->attrs & ~0x07u) | duetos_cvt_ansi_to_win3((unsigned short)(p - 30)));
        else if (p == 39)
            st->attrs = (unsigned short)((st->attrs & ~0x07u) | 0x07u);
        else if (p >= 40 && p <= 47)
            st->attrs = (unsigned short)((st->attrs & ~0x70u) |
                                         ((unsigned)duetos_cvt_ansi_to_win3((unsigned short)(p - 40)) << 4));
        else if (p == 49)
            st->attrs = (unsigned short)(st->attrs & ~0xF0u);
        else if (p >= 90 && p <= 97)
            st->attrs =
                (unsigned short)((st->attrs & ~0x0Fu) | duetos_cvt_ansi_to_win3((unsigned short)(p - 90)) | 0x08u);
        else if (p >= 100 && p <= 107)
            st->attrs = (unsigned short)((st->attrs & ~0xF0u) |
                                         ((unsigned)duetos_cvt_ansi_to_win3((unsigned short)(p - 100)) << 4) | 0x80u);
        /* Other SGR codes (underline, reverse, ...) have no Win32
         * attribute-word representation at v0 — ignored. */
        ++i;
    }
}

static inline void duetos_cvt_csi_final(duetos_cvt_state* st, unsigned char fin)
{
    const unsigned count = (st->nparams == 0 && !st->have_digit) ? 0u : (unsigned)(st->nparams + 1);
    const unsigned max_x = (st->cols > 0) ? (unsigned)(st->cols - 1) : 0u;
    const unsigned max_y = (st->rows > 0) ? (unsigned)(st->rows - 1) : 0u;

    if (st->priv)
    {
        /* Private sequences (ESC[?25l etc.) touch neither cursor
         * nor attributes in the mirror. */
        duetos_cvt_seq_reset(st);
        return;
    }

    switch (fin)
    {
    case 'A': /* CUU */
    {
        const unsigned n = duetos_cvt_param_or(st, count, 0, 1);
        st->cur_y = (short)(((unsigned)st->cur_y > n) ? ((unsigned)st->cur_y - n) : 0u);
        break;
    }
    case 'B': /* CUD */
    {
        const unsigned n = duetos_cvt_param_or(st, count, 0, 1);
        const unsigned y = (unsigned)st->cur_y + n;
        st->cur_y = (short)((y > max_y) ? max_y : y);
        break;
    }
    case 'C': /* CUF */
    {
        const unsigned n = duetos_cvt_param_or(st, count, 0, 1);
        const unsigned x = (unsigned)st->cur_x + n;
        st->cur_x = (short)((x > max_x) ? max_x : x);
        break;
    }
    case 'D': /* CUB */
    {
        const unsigned n = duetos_cvt_param_or(st, count, 0, 1);
        st->cur_x = (short)(((unsigned)st->cur_x > n) ? ((unsigned)st->cur_x - n) : 0u);
        break;
    }
    case 'H':
    case 'f': /* CUP / HVP: 1-based row;col, defaults 1;1 */
    {
        const unsigned r = duetos_cvt_param_or(st, count, 0, 1);
        const unsigned c = duetos_cvt_param_or(st, count, 1, 1);
        const unsigned y = (r > 0) ? (r - 1) : 0u;
        const unsigned x = (c > 0) ? (c - 1) : 0u;
        st->cur_y = (short)((y > max_y) ? max_y : y);
        st->cur_x = (short)((x > max_x) ? max_x : x);
        break;
    }
    case 'J': /* ED — erase mutates the downstream grid only */
    case 'K': /* EL — cursor and attrs unchanged */
        break;
    case 'm':
        duetos_cvt_apply_sgr(st, count);
        break;
    default:
        /* Unsupported CSI final — the sequence was consumed; the
         * mirror advertises only the handlers above. */
        break;
    }
    duetos_cvt_seq_reset(st);
}

static inline void duetos_cvt_ground_byte(duetos_cvt_state* st, unsigned char c)
{
    const short max_x = (st->cols > 0) ? (short)(st->cols - 1) : 0;
    const short max_y = (st->rows > 0) ? (short)(st->rows - 1) : 0;
    switch (c)
    {
    case 0x07: /* BEL */
        break;
    case 0x08: /* BS — never wraps to the previous row */
        if (st->cur_x > 0)
            st->cur_x--;
        break;
    case 0x09: /* HT — next 8-column stop */
    {
        short x = (short)((st->cur_x + 8) & ~7);
        st->cur_x = (x > max_x) ? max_x : x;
        break;
    }
    case 0x0A: /* LF */
    case 0x0B: /* VT */
    case 0x0C: /* FF — newline; scroll pins y at the bottom row */
        st->cur_x = 0;
        if (st->cur_y < max_y)
            st->cur_y++;
        break;
    case 0x0D: /* CR */
        st->cur_x = 0;
        break;
    case 0x1B:
        st->pstate = DUETOS_CVT_ESCAPE;
        break;
    default:
        if (c >= 0x20)
        {
            /* Printable advance with deferred wrap, matching the
             * kernel Terminal's PutCp: the cursor may sit at
             * x == cols after filling the last column; the NEXT
             * glyph performs the wrap. Bytes >= 0x80 count one
             * cell each — WriteConsoleW already strips to the low
             * byte, so multi-byte UTF-8 never reaches this path. */
            if (st->cur_x >= st->cols)
            {
                st->cur_x = 0;
                if (st->cur_y < max_y)
                    st->cur_y++;
            }
            st->cur_x++;
        }
        break;
    }
}

static inline void duetos_cvt_feed(duetos_cvt_state* st, const unsigned char* bytes, unsigned len)
{
    for (unsigned i = 0; i < len; ++i)
    {
        const unsigned char c = bytes[i];
        switch (st->pstate)
        {
        case DUETOS_CVT_GROUND:
            duetos_cvt_ground_byte(st, c);
            break;
        case DUETOS_CVT_ESCAPE:
            if (c == '[')
            {
                st->pstate = DUETOS_CVT_CSI;
            }
            else
            {
                /* Non-CSI escape (charset select, OSC, ...) — drop
                 * the introducer byte and return to ground. // GAP:
                 * multi-byte OSC payloads are not skipped, so an
                 * OSC title string would advance the cursor mirror
                 * — revisit if a PE workload emits OSC. */
                duetos_cvt_seq_reset(st);
            }
            break;
        case DUETOS_CVT_CSI:
            if (c >= '0' && c <= '9')
            {
                if (st->nparams < DUETOS_CVT_MAX_PARAMS)
                {
                    unsigned v = (unsigned)st->params[st->nparams] * 10u + (unsigned)(c - '0');
                    st->params[st->nparams] = (unsigned short)((v > 9999u) ? 9999u : v);
                }
                st->have_digit = 1;
            }
            else if (c == ';')
            {
                if (st->nparams < DUETOS_CVT_MAX_PARAMS - 1)
                    st->nparams++;
                st->have_digit = 0;
            }
            else if (c >= '<' && c <= '?')
            {
                st->priv = 1;
            }
            else if (c >= 0x20 && c <= 0x2F)
            {
                /* Intermediate bytes — consumed. */
            }
            else if (c >= 0x40 && c <= 0x7E)
            {
                duetos_cvt_csi_final(st, c);
            }
            else
            {
                /* Control byte inside CSI or malformed sequence —
                 * abandon the sequence. */
                duetos_cvt_seq_reset(st);
            }
            break;
        default:
            duetos_cvt_seq_reset(st);
            break;
        }
    }
}
