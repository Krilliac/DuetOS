#include "arch/x86_64/serial.h"

#include "arch/x86_64/cpu.h"

namespace duetos::arch
{

namespace
{

/* 16550 register offsets from the base port. */
constexpr u16 kRegData = 0;         // DLAB=0: RBR/THR
constexpr u16 kRegInterruptEn = 1;  // DLAB=0: IER
constexpr u16 kRegFifoControl = 2;  // FCR (write-only)
constexpr u16 kRegLineControl = 3;  // LCR
constexpr u16 kRegModemControl = 4; // MCR
constexpr u16 kRegLineStatus = 5;   // LSR

constexpr u8 kLsrTransmitEmpty = 1u << 5;
constexpr u8 kLcrDlab = 1u << 7;
constexpr u8 kLcr8N1 = 0b00000011;

} // namespace

void SerialInit()
{
    // Disable all UART interrupts — we poll.
    Outb(kCom1Port + kRegInterruptEn, 0x00);

    // Enable DLAB so the next two writes set the divisor.
    Outb(kCom1Port + kRegLineControl, kLcrDlab);

    // 115200 baud: divisor = 115200 / 115200 = 1.
    Outb(kCom1Port + kRegData, 0x01);
    Outb(kCom1Port + kRegInterruptEn, 0x00);

    // 8 data bits, no parity, 1 stop bit. Clears DLAB in the same write.
    Outb(kCom1Port + kRegLineControl, kLcr8N1);

    // Enable + clear FIFOs, 14-byte trigger level.
    Outb(kCom1Port + kRegFifoControl, 0xC7);

    // Assert RTS and DTR, enable auxiliary output 2 (required for IRQ routing
    // on real hardware even though we don't use interrupts here).
    Outb(kCom1Port + kRegModemControl, 0x0B);
}

void SerialWriteByte(u8 byte)
{
    while ((Inb(kCom1Port + kRegLineStatus) & kLsrTransmitEmpty) == 0)
    {
        // Spin until the transmitter holding register is empty.
    }
    Outb(kCom1Port + kRegData, byte);
}

void SerialWrite(const char* str)
{
    if (str == nullptr)
    {
        return;
    }

    for (const char* p = str; *p != '\0'; ++p)
    {
        // Upgrade LF to CRLF so terminals render boot logs with predictable
        // line breaks. Removing this will make output look line-jittered in
        // some terminals (notably minicom without auto-CR).
        if (*p == '\n')
        {
            SerialWriteByte('\r');
        }
        SerialWriteByte(static_cast<u8>(*p));
    }
}

void SerialWriteN(const char* data, u64 len)
{
    if (data == nullptr || len == 0)
    {
        return;
    }

    for (u64 i = 0; i < len; ++i)
    {
        const char ch = data[i];

        // Keep parity with SerialWrite(const char*): embedded NUL bytes
        // are treated as non-printing and skipped.
        if (ch == '\0')
        {
            continue;
        }

        // Upgrade LF to CRLF for terminal-friendly line breaks.
        if (ch == '\n')
        {
            SerialWriteByte('\r');
        }
        SerialWriteByte(static_cast<u8>(ch));
    }
}

void SerialWriteHex(u64 value)
{
    static constexpr char kDigits[] = "0123456789abcdef";

    SerialWriteByte('0');
    SerialWriteByte('x');

    for (int shift = 60; shift >= 0; shift -= 4)
    {
        SerialWriteByte(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
    }
}

} // namespace duetos::arch
