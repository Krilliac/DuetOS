/*
 * userland/libs/kernel32/kernel32_console_input.h
 *
 * Freestanding cooked-byte -> Win32 key-stroke translation core for
 * the kernel32 console-input surface (ReadConsoleInput /
 * PeekConsoleInput). The kernel's stdin path (SYS_STDIN_READ
 * draining the per-process stdin ring fed by the kbd-reader task)
 * delivers cooked ASCII bytes, not scan codes — this header derives
 * the KEY_EVENT_RECORD fields (virtual-key code, character, control
 * key state) a Win32 caller expects, assuming a US layout.
 *
 * // GAP: wVirtualScanCode is not derivable from a cooked byte — the
 * consumer stamps 0. Revisit if the kernel ever forwards raw
 * make/break codes to ring 3.
 *
 * Hosted unit test: tests/host/test_kernel32_console_input.cpp.
 */
#pragma once

/* dwControlKeyState bits (Win32 wincon.h values). */
enum
{
    DUETOS_KEY_SHIFT_PRESSED = 0x0010,
    DUETOS_KEY_LEFT_CTRL_PRESSED = 0x0008
};

typedef struct duetos_key_stroke
{
    unsigned short vk;         /* Win32 virtual-key code */
    unsigned short ascii;      /* character delivered in uChar */
    unsigned short ctrl_state; /* SHIFT / LEFT_CTRL bits above */
} duetos_key_stroke;

/* Map one cooked ASCII byte to the key stroke that would have
 * produced it on a US keyboard. Always fills `out` and returns 1
 * (unmappable bytes become vk=0 char-only strokes so no input is
 * silently dropped). */
static inline int duetos_console_byte_to_stroke(unsigned char c, duetos_key_stroke* out)
{
    switch (c)
    {
    case '\n':
    case '\r':
        /* The kernel stdin ring pushes '\n' for Enter; Win32
         * KEY_EVENT delivers VK_RETURN with uChar '\r'. */
        out->vk = 0x0D;
        out->ascii = '\r';
        out->ctrl_state = 0;
        break;
    case '\t':
        out->vk = 0x09;
        out->ascii = '\t';
        out->ctrl_state = 0;
        break;
    case 0x08:
    case 0x7F:
        /* The kbd-reader pushes DEL (0x7F) for Backspace. */
        out->vk = 0x08;
        out->ascii = 0x08;
        out->ctrl_state = 0;
        break;
    case 0x1B:
        out->vk = 0x1B;
        out->ascii = 0x1B;
        out->ctrl_state = 0;
        break;
    case ' ':
        out->vk = 0x20;
        out->ascii = ' ';
        out->ctrl_state = 0;
        break;
    case ')':
        out->vk = 0x30;
        out->ascii = ')';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '!':
        out->vk = 0x31;
        out->ascii = '!';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '@':
        out->vk = 0x32;
        out->ascii = '@';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '#':
        out->vk = 0x33;
        out->ascii = '#';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '$':
        out->vk = 0x34;
        out->ascii = '$';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '%':
        out->vk = 0x35;
        out->ascii = '%';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '^':
        out->vk = 0x36;
        out->ascii = '^';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '&':
        out->vk = 0x37;
        out->ascii = '&';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '*':
        out->vk = 0x38;
        out->ascii = '*';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '(':
        out->vk = 0x39;
        out->ascii = '(';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case ';':
        out->vk = 0xBA; /* VK_OEM_1 */
        out->ascii = ';';
        out->ctrl_state = 0;
        break;
    case ':':
        out->vk = 0xBA;
        out->ascii = ':';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '=':
        out->vk = 0xBB; /* VK_OEM_PLUS */
        out->ascii = '=';
        out->ctrl_state = 0;
        break;
    case '+':
        out->vk = 0xBB;
        out->ascii = '+';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case ',':
        out->vk = 0xBC; /* VK_OEM_COMMA */
        out->ascii = ',';
        out->ctrl_state = 0;
        break;
    case '<':
        out->vk = 0xBC;
        out->ascii = '<';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '-':
        out->vk = 0xBD; /* VK_OEM_MINUS */
        out->ascii = '-';
        out->ctrl_state = 0;
        break;
    case '_':
        out->vk = 0xBD;
        out->ascii = '_';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '.':
        out->vk = 0xBE; /* VK_OEM_PERIOD */
        out->ascii = '.';
        out->ctrl_state = 0;
        break;
    case '>':
        out->vk = 0xBE;
        out->ascii = '>';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '/':
        out->vk = 0xBF; /* VK_OEM_2 */
        out->ascii = '/';
        out->ctrl_state = 0;
        break;
    case '?':
        out->vk = 0xBF;
        out->ascii = '?';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '`':
        out->vk = 0xC0; /* VK_OEM_3 */
        out->ascii = '`';
        out->ctrl_state = 0;
        break;
    case '~':
        out->vk = 0xC0;
        out->ascii = '~';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '[':
        out->vk = 0xDB; /* VK_OEM_4 */
        out->ascii = '[';
        out->ctrl_state = 0;
        break;
    case '{':
        out->vk = 0xDB;
        out->ascii = '{';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '\\':
        out->vk = 0xDC; /* VK_OEM_5 */
        out->ascii = '\\';
        out->ctrl_state = 0;
        break;
    case '|':
        out->vk = 0xDC;
        out->ascii = '|';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case ']':
        out->vk = 0xDD; /* VK_OEM_6 */
        out->ascii = ']';
        out->ctrl_state = 0;
        break;
    case '}':
        out->vk = 0xDD;
        out->ascii = '}';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    case '\'':
        out->vk = 0xDE; /* VK_OEM_7 */
        out->ascii = '\'';
        out->ctrl_state = 0;
        break;
    case '"':
        out->vk = 0xDE;
        out->ascii = '"';
        out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        break;
    default:
        if (c >= 'a' && c <= 'z')
        {
            out->vk = (unsigned short)(c - 0x20);
            out->ascii = c;
            out->ctrl_state = 0;
        }
        else if (c >= 'A' && c <= 'Z')
        {
            out->vk = c;
            out->ascii = c;
            out->ctrl_state = DUETOS_KEY_SHIFT_PRESSED;
        }
        else if (c >= '0' && c <= '9')
        {
            out->vk = c;
            out->ascii = c;
            out->ctrl_state = 0;
        }
        else if (c >= 0x01 && c <= 0x1A)
        {
            /* Remaining C0 bytes: Ctrl+letter. */
            out->vk = (unsigned short)('A' + (c - 1));
            out->ascii = c;
            out->ctrl_state = DUETOS_KEY_LEFT_CTRL_PRESSED;
        }
        else
        {
            out->vk = 0;
            out->ascii = c;
            out->ctrl_state = 0;
        }
        break;
    }
    return 1;
}
