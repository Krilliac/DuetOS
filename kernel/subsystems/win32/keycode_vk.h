#pragma once

#include "drivers/input/ps2kbd.h"
#include "util/types.h"

/*
 * DuetOS KeyCode -> Win32 Virtual-Key (VK) translation.
 *
 * The PS/2 keyboard driver (ps2kbd.h) produces logical KeyCode values
 * that are NOT Win32 virtual-key codes. ASCII printable keys largely
 * overlap, but non-ASCII keys diverge (e.g. kKeyF1 == 0x10A vs
 * VK_F1 == 0x70), and kKeyEnter (0x0A) != VK_RETURN (0x0D).
 *
 * Win32 PEs expect WM_KEYDOWN/WM_KEYUP wParam to carry a VK code.
 * This header provides the translation at the point where the kernel
 * posts key messages to PE windows.
 *
 * Added 2026-07-29 for the WM_KEYDOWN VK translation slice.
 */

namespace duetos::subsystems::win32
{

// Win32 Virtual-Key constants referenced by the translation table.
namespace vk
{
constexpr u16 kReturn = 0x0D;
constexpr u16 kPrior = 0x21;
constexpr u16 kNext = 0x22;
constexpr u16 kEnd = 0x23;
constexpr u16 kHome = 0x24;
constexpr u16 kLeft = 0x25;
constexpr u16 kUp = 0x26;
constexpr u16 kRight = 0x27;
constexpr u16 kDown = 0x28;
constexpr u16 kInsert = 0x2D;
constexpr u16 kDelete = 0x2E;
constexpr u16 kF1 = 0x70;
constexpr u16 kOem1 = 0xBA;
constexpr u16 kOemPlus = 0xBB;
constexpr u16 kOemComma = 0xBC;
constexpr u16 kOemMinus = 0xBD;
constexpr u16 kOemPeriod = 0xBE;
constexpr u16 kOem2 = 0xBF;
constexpr u16 kOem3 = 0xC0;
constexpr u16 kOem4 = 0xDB;
constexpr u16 kOem5 = 0xDC;
constexpr u16 kOem6 = 0xDD;
constexpr u16 kOem7 = 0xDE;
} // namespace vk

/// Translate a DuetOS KeyCode to a Win32 virtual-key code.
/// Returns 0 for unmapped keys.
inline u16 KeyCodeToVk(u16 code)
{
    using namespace drivers::input;

    // Non-ASCII special keys (0x100 range).
    if (code >= kKeyArrowUp)
    {
        switch (code)
        {
        case kKeyArrowUp:
            return vk::kUp;
        case kKeyArrowDown:
            return vk::kDown;
        case kKeyArrowLeft:
            return vk::kLeft;
        case kKeyArrowRight:
            return vk::kRight;
        case kKeyHome:
            return vk::kHome;
        case kKeyEnd:
            return vk::kEnd;
        case kKeyPageUp:
            return vk::kPrior;
        case kKeyPageDown:
            return vk::kNext;
        case kKeyInsert:
            return vk::kInsert;
        case kKeyDelete:
            return vk::kDelete;
        default:
            break;
        }
        // F1..F12: contiguous in both enums.
        if (code >= kKeyF1 && code <= kKeyF12)
            return static_cast<u16>(vk::kF1 + (code - kKeyF1));
        return 0;
    }

    // Control-character ASCII keys.
    if (code == kKeyEnter)
        return vk::kReturn;
    // Esc (0x1B), Backspace (0x08), Tab (0x09) are the same
    // in both DuetOS and Win32 — passthrough.
    if (code == kKeyEsc || code == kKeyBackspace || code == kKeyTab)
        return code;

    // ASCII letters -> uppercase VK (Win32 A-Z = 0x41-0x5A).
    if (code >= 'a' && code <= 'z')
        return static_cast<u16>(code - 'a' + 'A');
    if (code >= 'A' && code <= 'Z')
        return code;

    // Digits (0x30..0x39) and space (0x20) pass through.
    if ((code >= '0' && code <= '9') || code == ' ')
        return code;

    // Punctuation -> VK_OEM_*.
    switch (code)
    {
    case ';':
        return vk::kOem1;
    case '=':
        return vk::kOemPlus;
    case ',':
        return vk::kOemComma;
    case '-':
        return vk::kOemMinus;
    case '.':
        return vk::kOemPeriod;
    case '/':
        return vk::kOem2;
    case '`':
        return vk::kOem3;
    case '[':
        return vk::kOem4;
    case '\\':
        return vk::kOem5;
    case ']':
        return vk::kOem6;
    case '\'':
        return vk::kOem7;
    default:
        break;
    }

    // Shifted punctuation -> base digit VK. Win32 delivers
    // the unshifted VK for WM_KEYDOWN; the shifted character
    // goes in WM_CHAR.
    switch (code)
    {
    case '!':
        return u16('1');
    case '@':
        return u16('2');
    case '#':
        return u16('3');
    case '$':
        return u16('4');
    case '%':
        return u16('5');
    case '^':
        return u16('6');
    case '&':
        return u16('7');
    case '*':
        return u16('8');
    case '(':
        return u16('9');
    case ')':
        return u16('0');
    case ':':
        return vk::kOem1;
    case '+':
        return vk::kOemPlus;
    case '<':
        return vk::kOemComma;
    case '_':
        return vk::kOemMinus;
    case '>':
        return vk::kOemPeriod;
    case '?':
        return vk::kOem2;
    case '~':
        return vk::kOem3;
    case '{':
        return vk::kOem4;
    case '|':
        return vk::kOem5;
    case '}':
        return vk::kOem6;
    case '"':
        return vk::kOem7;
    default:
        break;
    }

    return 0;
}

} // namespace duetos::subsystems::win32
