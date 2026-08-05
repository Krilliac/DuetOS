// test_kernel32_console_input.cpp — hosted unit test for the cooked
// ASCII byte -> Win32 key-stroke translation core used by
// ReadConsoleInput / PeekConsoleInput in the userland kernel32.dll.
//
// Covers: userland/libs/kernel32/kernel32_console_input.h
//   (duetos_console_byte_to_stroke — VK derivation, uChar value and
//    SHIFT / LEFT_CTRL control-state bits for a US layout).

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/kernel32_console_input.h"

namespace
{

// Helper: translate one byte, return the stroke.
duetos_key_stroke tr(unsigned char c)
{
    duetos_key_stroke ks{};
    duetos_console_byte_to_stroke(c, &ks);
    return ks;
}

} // namespace

int main()
{
    // Lowercase letters: VK is the uppercase code, no modifiers.
    EXPECT_EQ(tr('a').vk, (unsigned short)0x41);
    EXPECT_EQ(tr('a').ascii, 'a');
    EXPECT_EQ(tr('a').ctrl_state, 0);
    EXPECT_EQ(tr('z').vk, (unsigned short)0x5A);
    EXPECT_EQ(tr('z').ascii, 'z');
    EXPECT_EQ(tr('z').ctrl_state, 0);

    // Uppercase letters: same VK, SHIFT held.
    EXPECT_EQ(tr('A').vk, (unsigned short)0x41);
    EXPECT_EQ(tr('A').ascii, 'A');
    EXPECT_EQ(tr('A').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('Z').vk, (unsigned short)0x5A);
    EXPECT_EQ(tr('Z').ascii, 'Z');
    EXPECT_EQ(tr('Z').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);

    // Digits and their shifted symbols share the digit VK.
    EXPECT_EQ(tr('5').vk, (unsigned short)0x35);
    EXPECT_EQ(tr('5').ascii, '5');
    EXPECT_EQ(tr('5').ctrl_state, 0);
    EXPECT_EQ(tr('%').vk, (unsigned short)0x35);
    EXPECT_EQ(tr('%').ascii, '%');
    EXPECT_EQ(tr('%').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('0').vk, (unsigned short)0x30);
    EXPECT_EQ(tr('0').ctrl_state, 0);
    EXPECT_EQ(tr(')').vk, (unsigned short)0x30);
    EXPECT_EQ(tr(')').ascii, ')');
    EXPECT_EQ(tr(')').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);

    // Enter: the stdin ring pushes '\n'; Win32 delivers VK_RETURN
    // with uChar '\r'.
    EXPECT_EQ(tr('\n').vk, (unsigned short)0x0D);
    EXPECT_EQ(tr('\n').ascii, '\r');
    EXPECT_EQ(tr('\n').ctrl_state, 0);
    EXPECT_EQ(tr('\r').vk, (unsigned short)0x0D);
    EXPECT_EQ(tr('\r').ascii, '\r');
    EXPECT_EQ(tr('\r').ctrl_state, 0);

    // Tab / Backspace (DEL and BS forms) / Escape / Space.
    EXPECT_EQ(tr('\t').vk, (unsigned short)0x09);
    EXPECT_EQ(tr('\t').ascii, '\t');
    EXPECT_EQ(tr('\t').ctrl_state, 0);
    EXPECT_EQ(tr(0x7F).vk, (unsigned short)0x08);
    EXPECT_EQ(tr(0x7F).ascii, 0x08);
    EXPECT_EQ(tr(0x7F).ctrl_state, 0);
    EXPECT_EQ(tr(0x08).vk, (unsigned short)0x08);
    EXPECT_EQ(tr(0x08).ascii, 0x08);
    EXPECT_EQ(tr(0x08).ctrl_state, 0);
    EXPECT_EQ(tr(0x1B).vk, (unsigned short)0x1B);
    EXPECT_EQ(tr(0x1B).ascii, 0x1B);
    EXPECT_EQ(tr(0x1B).ctrl_state, 0);
    EXPECT_EQ(tr(' ').vk, (unsigned short)0x20);
    EXPECT_EQ(tr(' ').ascii, ' ');
    EXPECT_EQ(tr(' ').ctrl_state, 0);

    // OEM punctuation, unshifted.
    EXPECT_EQ(tr(';').vk, (unsigned short)0xBA);
    EXPECT_EQ(tr(';').ascii, ';');
    EXPECT_EQ(tr(';').ctrl_state, 0);
    EXPECT_EQ(tr('=').vk, (unsigned short)0xBB);
    EXPECT_EQ(tr('=').ctrl_state, 0);
    EXPECT_EQ(tr(',').vk, (unsigned short)0xBC);
    EXPECT_EQ(tr(',').ctrl_state, 0);
    EXPECT_EQ(tr('-').vk, (unsigned short)0xBD);
    EXPECT_EQ(tr('-').ctrl_state, 0);
    EXPECT_EQ(tr('.').vk, (unsigned short)0xBE);
    EXPECT_EQ(tr('.').ctrl_state, 0);
    EXPECT_EQ(tr('/').vk, (unsigned short)0xBF);
    EXPECT_EQ(tr('/').ctrl_state, 0);
    EXPECT_EQ(tr('`').vk, (unsigned short)0xC0);
    EXPECT_EQ(tr('`').ctrl_state, 0);
    EXPECT_EQ(tr('[').vk, (unsigned short)0xDB);
    EXPECT_EQ(tr('[').ctrl_state, 0);
    EXPECT_EQ(tr('\\').vk, (unsigned short)0xDC);
    EXPECT_EQ(tr('\\').ascii, '\\');
    EXPECT_EQ(tr('\\').ctrl_state, 0);
    EXPECT_EQ(tr(']').vk, (unsigned short)0xDD);
    EXPECT_EQ(tr(']').ctrl_state, 0);
    EXPECT_EQ(tr('\'').vk, (unsigned short)0xDE);
    EXPECT_EQ(tr('\'').ctrl_state, 0);

    // OEM punctuation, shifted variants share the VK with SHIFT set.
    EXPECT_EQ(tr(':').vk, (unsigned short)0xBA);
    EXPECT_EQ(tr(':').ascii, ':');
    EXPECT_EQ(tr(':').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('+').vk, (unsigned short)0xBB);
    EXPECT_EQ(tr('+').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('<').vk, (unsigned short)0xBC);
    EXPECT_EQ(tr('<').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('_').vk, (unsigned short)0xBD);
    EXPECT_EQ(tr('_').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('>').vk, (unsigned short)0xBE);
    EXPECT_EQ(tr('>').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('?').vk, (unsigned short)0xBF);
    EXPECT_EQ(tr('?').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('~').vk, (unsigned short)0xC0);
    EXPECT_EQ(tr('~').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('{').vk, (unsigned short)0xDB);
    EXPECT_EQ(tr('{').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('|').vk, (unsigned short)0xDC);
    EXPECT_EQ(tr('|').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('}').vk, (unsigned short)0xDD);
    EXPECT_EQ(tr('}').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);
    EXPECT_EQ(tr('"').vk, (unsigned short)0xDE);
    EXPECT_EQ(tr('"').ctrl_state, DUETOS_KEY_SHIFT_PRESSED);

    // Ctrl+letter: C0 bytes 0x01..0x1A (minus the ones with their
    // own keys) map to the letter VK with LEFT_CTRL held and the
    // raw control byte as uChar.
    EXPECT_EQ(tr(0x03).vk, (unsigned short)0x43); // Ctrl+C
    EXPECT_EQ(tr(0x03).ascii, 0x03);
    EXPECT_EQ(tr(0x03).ctrl_state, DUETOS_KEY_LEFT_CTRL_PRESSED);
    EXPECT_EQ(tr(0x01).vk, (unsigned short)0x41); // Ctrl+A
    EXPECT_EQ(tr(0x01).ascii, 0x01);
    EXPECT_EQ(tr(0x01).ctrl_state, DUETOS_KEY_LEFT_CTRL_PRESSED);
    EXPECT_EQ(tr(0x1A).vk, (unsigned short)0x5A); // Ctrl+Z
    EXPECT_EQ(tr(0x1A).ascii, 0x1A);
    EXPECT_EQ(tr(0x1A).ctrl_state, DUETOS_KEY_LEFT_CTRL_PRESSED);

    // Unmappable bytes become vk=0 char-only strokes — never dropped.
    EXPECT_EQ(tr(0x00).vk, (unsigned short)0);
    EXPECT_EQ(tr(0x00).ascii, 0);
    EXPECT_EQ(tr(0x00).ctrl_state, 0);
    EXPECT_EQ(tr(0x1C).vk, (unsigned short)0);
    EXPECT_EQ(tr(0x1C).ascii, 0x1C);
    EXPECT_EQ(tr(0x1C).ctrl_state, 0);
    EXPECT_EQ(tr(0x80).vk, (unsigned short)0);
    EXPECT_EQ(tr(0x80).ascii, 0x80);
    EXPECT_EQ(tr(0x80).ctrl_state, 0);
    EXPECT_EQ(tr(0xFF).vk, (unsigned short)0);

    // Return value is 1 for every byte.
    duetos_key_stroke ks{};
    EXPECT_EQ(duetos_console_byte_to_stroke('a', &ks), 1);
    EXPECT_EQ(duetos_console_byte_to_stroke(0x00, &ks), 1);
    EXPECT_EQ(duetos_console_byte_to_stroke(0xFF, &ks), 1);

    return duetos_host_test::finish_main("kernel32_console_input");
}
