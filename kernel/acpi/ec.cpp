/*
 * DuetOS — ACPI Embedded Controller driver (v0): implementation.
 * See ec.h for the transport, presence model, and GAPs.
 */

#include "acpi/ec.h"

#include "acpi/aml.h"
#include "acpi/aml_eval.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "time/timekeeper.h"

namespace duetos::acpi
{

namespace
{

// De-facto-standard ACPI EC IO ports (GAP: not parsed from ECDT/_CRS).
constexpr u16 kEcCmdPort = 0x66;  // EC_SC: write=command, read=status
constexpr u16 kEcDataPort = 0x62; // EC_DATA

// EC_SC status-register bits.
constexpr u8 kEcObf = 0x01; // output buffer full (EC → host data ready)
constexpr u8 kEcIbf = 0x02; // input buffer full (host → EC not yet drained)

// EC commands.
constexpr u8 kEcCmdRead = 0x80;  // RD_EC
constexpr u8 kEcCmdWrite = 0x81; // WR_EC
constexpr u8 kEcCmdQuery = 0x84; // CMD_QUERY — returns pending query byte

// Per-phase timeout. The EC is slow (tens of µs typical) but a wedged
// or absent controller must not hang the boot — cap each handshake.
constexpr u64 kEcTimeoutNs = 100ULL * 1000 * 1000; // 100 ms

constinit bool g_inited = false;
constinit bool g_present = false;

u8 EcStatus()
{
    return arch::Inb(kEcCmdPort);
}

// Spin until (status & mask) == want, or the deadline elapses.
bool EcWait(u8 mask, u8 want)
{
    const u64 deadline = time::MonotonicNs() + kEcTimeoutNs;
    while ((EcStatus() & mask) != want)
    {
        if (time::MonotonicNs() >= deadline)
            return false;
        arch::Inb(0x80); // ~1 µs IO-port delay
    }
    return true;
}

bool EcReadByte(u8 addr, u8* out)
{
    if (!g_present)
        return false;
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcCmdPort, kEcCmdRead);
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcDataPort, addr);
    if (!EcWait(kEcObf, kEcObf))
        return false;
    *out = arch::Inb(kEcDataPort);
    return true;
}

bool EcWriteByte(u8 addr, u8 val)
{
    if (!g_present)
        return false;
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcCmdPort, kEcCmdWrite);
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcDataPort, addr);
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcDataPort, val);
    if (!EcWait(kEcIbf, 0))
        return false;
    return true;
}

// Read the next pending EC query byte. Used by the SCI handler
// when the EC asserts SCI_EVT in EC_SC. The protocol:
//   1. Wait for IBF=0 (host write side drained).
//   2. Issue CMD_QUERY (0x84) to EC_SC.
//   3. Wait for OBF=1 (EC has placed the query byte in EC_DATA).
//   4. Read EC_DATA — the byte is the `_Qxx` index (e.g. 0x12 →
//      the firmware's `_Q12` AML method should run next).
// Byte 0 means "no event pending" — the EC ack'd CMD_QUERY but
// had nothing queued. This is the canonical drain-complete signal.
//
// Sources: ACPI 6.5 §12.3 (EC command set), Linux drivers/acpi/ec.c
// (acpi_ec_query_response), FreeBSD sys/dev/acpica/acpi_ec.c
// (EcGpeQueryHandler).
bool EcReadQueryByteImpl(u8* out)
{
    if (!g_present || out == nullptr)
        return false;
    if (!EcWait(kEcIbf, 0))
        return false;
    arch::Outb(kEcCmdPort, kEcCmdQuery);
    if (!EcWait(kEcObf, kEcObf))
        return false;
    *out = arch::Inb(kEcDataPort);
    return true;
}

// AML EmbeddedControl region handler. EC space is byte-addressed
// (0x00..0xFF); width_bits is split into byte transactions and
// assembled little-endian. An out-of-range or failed access fails
// the whole call (the interpreter then yields Ones on a read).
bool EcRegionHandler(void* /*ctx*/, bool write, u64 address, u32 width_bits, u64* value)
{
    if (!g_present || value == nullptr)
        return false;
    const u32 nbytes = (width_bits + 7) / 8;
    if (nbytes == 0 || nbytes > 8 || address + nbytes > 0x100)
        return false;
    if (write)
    {
        for (u32 i = 0; i < nbytes; ++i)
            if (!EcWriteByte(u8(address + i), u8((*value >> (i * 8)) & 0xFF)))
                return false;
        return true;
    }
    u64 r = 0;
    for (u32 i = 0; i < nbytes; ++i)
    {
        u8 b = 0;
        if (!EcReadByte(u8(address + i), &b))
            return false;
        r |= u64(b) << (i * 8);
    }
    *value = r;
    return true;
}

bool NamespaceHasEcRegion()
{
    const u32 n = AmlRegionCount();
    for (u32 i = 0; i < n; ++i)
    {
        const AmlRegionInfo* r = AmlRegionAt(i);
        if (r != nullptr && r->space == AmlRegionSpace::EmbeddedControl)
            return true;
    }
    return false;
}

} // namespace

void AcpiEcInit()
{
    KLOG_TRACE_SCOPE("acpi/ec", "AcpiEcInit");
    if (g_inited)
        return;
    g_inited = true;

    g_present = NamespaceHasEcRegion();
    if (g_present)
    {
        AmlRegisterRegionHandler(AmlRegionSpace::EmbeddedControl, &EcRegionHandler, nullptr);
        // Drain any stale OBF byte so the first real transaction
        // starts from a known state. Bounded; ignore the result.
        if ((EcStatus() & kEcObf) != 0)
            (void)arch::Inb(kEcDataPort);
        KLOG_INFO("acpi/ec", "embedded controller present — EmbeddedControl handler registered (ports 0x66/0x62)");
        arch::SerialWrite("[acpi/ec] EC present: EmbeddedControl region handler registered (cmd=0x66 data=0x62)\n");
    }
    else
    {
        KLOG_INFO("acpi/ec", "no EmbeddedControl region declared — EC absent on this platform");
        arch::SerialWrite("[acpi/ec] no EmbeddedControl region — EC absent (e.g. QEMU); fields read Ones\n");
    }
}

bool AcpiEcPresent()
{
    return g_present;
}

bool AcpiEcRead(u8 addr, u8* value)
{
    if (value == nullptr)
        return false;
    return EcReadByte(addr, value);
}

bool AcpiEcWrite(u8 addr, u8 value)
{
    return EcWriteByte(addr, value);
}

bool AcpiEcReadQueryByte(u8* query)
{
    return EcReadQueryByteImpl(query);
}

bool AcpiEcDispatchPendingQuery()
{
    if (!g_present)
        return false;
    u8 q = 0;
    if (!EcReadQueryByteImpl(&q))
        return false;
    if (q == 0)
    {
        // Nothing pending — the CMD_QUERY drain is complete. Caller
        // should stop looping.
        return false;
    }
    // Build `\_GPE._Qxx` — two hex digits (uppercase) per ACPI
    // naming convention. The buffer is on the stack so we never
    // touch the heap from a path that may run early in boot.
    char name[12]; // "\\_GPE._Qhh\0"
    name[0] = '\\';
    name[1] = '_';
    name[2] = 'G';
    name[3] = 'P';
    name[4] = 'E';
    name[5] = '.';
    name[6] = '_';
    name[7] = 'Q';
    static const char kHex[] = "0123456789ABCDEF";
    name[8] = kHex[(q >> 4) & 0xF];
    name[9] = kHex[q & 0xF];
    name[10] = '\0';

    if (AmlNamespaceFind(name) == nullptr)
    {
        // Firmware emitted a query whose method isn't in the
        // namespace. Not fatal — some firmwares emit spurious
        // events. Log once per distinct query so a real shape
        // surfaces. Caller still sees "we drained a byte" via
        // `q != 0`, but no method ran.
        KLOG_ONCE_WARN_V("acpi/ec", "EC query has no matching \\_GPE._Qxx method; ignoring", q);
        // Return TRUE — we drained one query byte from the EC, so
        // the worker should loop again to consume any further
        // queued events. False would terminate the drain loop
        // even though more events might be pending.
        return true;
    }

    AmlValue result;
    if (!AmlEvaluate(name, nullptr, 0, &result).has_value())
    {
        // AML evaluation faulted. Log + continue draining; the
        // EC has more events queued and we don't want to wedge
        // the SCI handler on one bad method.
        KLOG_WARN_V("acpi/ec", "AML evaluation of EC _Qxx method failed; ignoring", q);
    }
    return true;
}

void AcpiEcSelfTest()
{
    AcpiEcInit();
    const bool present_first = g_present;
    AcpiEcInit(); // idempotent — must not change state
    if (g_present != present_first)
        core::Panic("acpi/ec", "selftest: AcpiEcInit not idempotent");

    if (!g_present)
    {
        // Absent-EC contract: reads fail cleanly, no hang/fault.
        u8 b = 0xAB;
        if (AcpiEcRead(0x00, &b))
            core::Panic("acpi/ec", "selftest: read succeeded with no EC present");
        if (b != 0xAB)
            core::Panic("acpi/ec", "selftest: failed read clobbered the caller's buffer");
        // Same contract for the new query-byte read + dispatch:
        // absent EC must fail cleanly with no IO-port poll.
        u8 q = 0xCD;
        if (AcpiEcReadQueryByte(&q))
            core::Panic("acpi/ec", "selftest: query-read succeeded with no EC present");
        if (q != 0xCD)
            core::Panic("acpi/ec", "selftest: failed query-read clobbered caller's buffer");
        if (AcpiEcDispatchPendingQuery())
            core::Panic("acpi/ec", "selftest: dispatch returned true with no EC present");
        // Null-buffer guard on the query reader.
        if (AcpiEcReadQueryByte(nullptr))
            core::Panic("acpi/ec", "selftest: query-read accepted null buffer");
    }
    arch::SerialWrite("[acpi/ec] selftest PASS (ec=");
    arch::SerialWrite(g_present ? "present" : "absent");
    arch::SerialWrite(")\n");
    KLOG_INFO_V("acpi/ec", "selftest PASS — ec present?", g_present ? 1 : 0);
}

} // namespace duetos::acpi
