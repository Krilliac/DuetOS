#include "arch/x86_64/serial.h"

#include "arch/x86_64/cpu.h"
#include "sync/spinlock.h"

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

// Per-port lock. SpinLockAcquire saves+disables IRQs so no IRQ
// handler can preempt a SerialWrite on this CPU and self-deadlock.
// Cross-CPU contention falls through to busy-wait.
duetos::sync::SpinLock g_serial_lock{};

// Set by SerialEnterPanicMode; checked at every Write* entry. Once
// flipped, every subsequent Write* skips the lock entirely. The kernel
// halts before clearing it. Volatile because we read it from arbitrary
// contexts (NMI handler may race with the setter on another CPU).
volatile u32 g_serial_panic_mode = 0;

// Drive the UART directly. No locking, no panic-mode check — the
// callers above have already decided whether they hold the lock or
// have bypassed it. Each byte spins on the LSR transmit-empty bit
// until the previous byte has cleared the THR.
void WriteByteRaw(u8 byte)
{
    while ((Inb(kCom1Port + kRegLineStatus) & kLsrTransmitEmpty) == 0)
    {
        // Spin until the transmitter holding register is empty.
    }
    Outb(kCom1Port + kRegData, byte);
}

void WriteCharRaw(char c)
{
    if (c == '\0')
    {
        return;
    }
    if (c == '\n')
    {
        WriteByteRaw('\r');
    }
    WriteByteRaw(static_cast<u8>(c));
}

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

void SerialEnterPanicMode()
{
    g_serial_panic_mode = 1;
}

void SerialWriteByte(u8 byte)
{
    if (g_serial_panic_mode)
    {
        WriteByteRaw(byte);
        return;
    }
    duetos::sync::SpinLockGuard guard(g_serial_lock);
    WriteByteRaw(byte);
}

void SerialWrite(const char* str)
{
    if (str == nullptr)
    {
        return;
    }

    if (g_serial_panic_mode)
    {
        for (const char* p = str; *p != '\0'; ++p)
        {
            WriteCharRaw(*p);
        }
        return;
    }

    duetos::sync::SpinLockGuard guard(g_serial_lock);
    for (const char* p = str; *p != '\0'; ++p)
    {
        WriteCharRaw(*p);
    }
}

void SerialWriteN(const char* data, u64 len)
{
    if (data == nullptr || len == 0)
    {
        return;
    }

    if (g_serial_panic_mode)
    {
        for (u64 i = 0; i < len; ++i)
        {
            WriteCharRaw(data[i]);
        }
        return;
    }

    duetos::sync::SpinLockGuard guard(g_serial_lock);
    for (u64 i = 0; i < len; ++i)
    {
        WriteCharRaw(data[i]);
    }
}

void SerialWriteHex(u64 value)
{
    static constexpr char kDigits[] = "0123456789abcdef";

    if (g_serial_panic_mode)
    {
        WriteByteRaw('0');
        WriteByteRaw('x');
        for (int shift = 60; shift >= 0; shift -= 4)
        {
            WriteByteRaw(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
        }
        return;
    }

    duetos::sync::SpinLockGuard guard(g_serial_lock);
    WriteByteRaw('0');
    WriteByteRaw('x');
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        WriteByteRaw(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
    }
}

} // namespace duetos::arch
