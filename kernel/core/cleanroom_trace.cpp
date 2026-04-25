#include "cleanroom_trace.h"

#include "../arch/x86_64/serial.h"
#include "../sync/spinlock.h"
#include "log_names.h"
#include "result.h"

namespace duetos::core
{

namespace
{

constinit sync::SpinLock g_cleanroom_lock = {};

// Sticky boot region — fills once, then locks. Captures the
// driver init / PE-loader / firmware-loader events that fire
// during the early-boot blast and would otherwise vanish under
// syscall load before any dump runs.
constinit CleanroomTraceEntry g_boot[kCleanroomTraceBootCapacity] = {};
constinit u32 g_boot_count = 0;

// Rolling tail — wraps over the most recent
// kCleanroomTraceRollingCapacity events for steady-state
// observation.
constinit CleanroomTraceEntry g_rolling[kCleanroomTraceRollingCapacity] = {};
constinit u32 g_rolling_head = 0;
constinit u32 g_rolling_count = 0;

void CopyBounded(char* dst, u32 cap, const char* src)
{
    if (dst == nullptr || cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

void WriteEntry(CleanroomTraceEntry& e, const char* subsystem, const char* event, u64 a, u64 b, u64 c)
{
    CopyBounded(e.subsystem, sizeof(e.subsystem), subsystem);
    CopyBounded(e.event, sizeof(e.event), event);
    e.a = a;
    e.b = b;
    e.c = c;
}

} // namespace

void CleanroomTraceRecord(const char* subsystem, const char* event, u64 a, u64 b, u64 c)
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    if (g_boot_count < kCleanroomTraceBootCapacity)
    {
        WriteEntry(g_boot[g_boot_count], subsystem, event, a, b, c);
        ++g_boot_count;
        return;
    }
    WriteEntry(g_rolling[g_rolling_head], subsystem, event, a, b, c);
    g_rolling_head = (g_rolling_head + 1) % kCleanroomTraceRollingCapacity;
    if (g_rolling_count < kCleanroomTraceRollingCapacity)
        ++g_rolling_count;
}

u32 CleanroomTraceCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_boot_count + g_rolling_count;
}

u32 CleanroomTraceBootCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_boot_count;
}

u32 CleanroomTraceRollingCount()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    return g_rolling_count;
}

bool CleanroomTraceRead(u32 index, CleanroomTraceEntry* out)
{
    if (out == nullptr)
        return false;
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    if (index < g_boot_count)
    {
        *out = g_boot[index];
        return true;
    }
    const u32 rolling_index = index - g_boot_count;
    if (rolling_index >= g_rolling_count)
        return false;
    const u32 oldest =
        (g_rolling_head + kCleanroomTraceRollingCapacity - g_rolling_count) % kCleanroomTraceRollingCapacity;
    const u32 slot = (oldest + rolling_index) % kCleanroomTraceRollingCapacity;
    *out = g_rolling[slot];
    return true;
}

void CleanroomTraceClear()
{
    sync::SpinLockGuard guard(g_cleanroom_lock);
    (void)guard;
    g_boot_count = 0;
    g_rolling_head = 0;
    g_rolling_count = 0;
    for (u32 i = 0; i < kCleanroomTraceBootCapacity; ++i)
        g_boot[i] = {};
    for (u32 i = 0; i < kCleanroomTraceRollingCapacity; ++i)
        g_rolling[i] = {};
}

namespace
{

// Tiny string-equal helper. Trace entries store
// kCleanroomTraceTextMax-bounded names so an unbounded strcmp
// would walk past the buffer; this stops at the trailing NUL
// the recorder always plants.
bool SubEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    for (u32 i = 0; i < kCleanroomTraceTextMax + 1; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return false;
}

void WriteHex(u64 v)
{
    arch::SerialWriteHex(v);
}

void WriteDec(u64 v)
{
    if (v == 0)
    {
        arch::SerialWrite("0");
        return;
    }
    char buf[24];
    u32 n = 0;
    while (v > 0 && n < sizeof(buf))
    {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    char rev[24];
    for (u32 i = 0; i < n; ++i)
        rev[i] = buf[n - 1 - i];
    rev[n] = '\0';
    arch::SerialWrite(rev);
}

// Per-subsystem decoders. Each one knows how to interpret the
// (a, b, c) tuple for its events and writes a human-readable
// trailer to serial. If a subsystem has no decoder or the event
// isn't one we recognise, the caller falls back to printing the
// raw a/b/c hex.

bool DecodeSyscall(const CleanroomTraceEntry& e)
{
    const bool native = SubEq(e.event, "native-dispatch");
    const bool linuxd = SubEq(e.event, "linux-dispatch");
    if (!native && !linuxd)
        return false;
    arch::SerialWrite(native ? "  " : "  ");
    arch::SerialWrite(native ? SyscallName(e.a) : LinuxSyscallName(e.a));
    arch::SerialWrite(" pid=");
    WriteDec(e.b);
    arch::SerialWrite(" rip=");
    WriteHex(e.c);
    return true;
}

bool DecodeShell(const CleanroomTraceEntry& e)
{
    if (!SubEq(e.event, "command"))
        return false;
    arch::SerialWrite("  cmd_hash=");
    WriteHex(e.a);
    arch::SerialWrite(" argc=");
    WriteDec(e.b);
    arch::SerialWrite(" arg1_hash=");
    WriteHex(e.c);
    return true;
}

bool DecodeWifi(const CleanroomTraceEntry& e)
{
    arch::SerialWrite("  iface=");
    WriteDec(e.a);
    if (SubEq(e.event, "scan-ok") || SubEq(e.event, "scan-invalid"))
    {
        arch::SerialWrite(SubEq(e.event, "scan-ok") ? " count=" : " max_results=");
        WriteDec(e.b);
        return true;
    }
    if (SubEq(e.event, "connect-ok") || SubEq(e.event, "connect-driver-fail"))
    {
        arch::SerialWrite(" security=");
        arch::SerialWrite(WifiSecurityName(e.b));
        return true;
    }
    if (SubEq(e.event, "connect-bad-psk"))
    {
        arch::SerialWrite(" psk_len=");
        WriteDec(e.b);
        return true;
    }
    return true; // iface= alone is enough for register-*, disconnect-*, scan-no-backend, etc.
}

bool DecodeFwLoader(const CleanroomTraceEntry& e)
{
    if (!SubEq(e.event, "path-attempt"))
        return false;
    arch::SerialWrite("  result=");
    arch::SerialWrite(ErrorCodeName(static_cast<ErrorCode>(static_cast<i32>(e.a))));
    arch::SerialWrite(" policy=");
    arch::SerialWrite(FwSourcePolicyName(e.b));
    return true;
}

bool DecodeE1000(const CleanroomTraceEntry& e)
{
    // Recording sites in kernel/drivers/net/net.cpp:
    //   ivar-programmed     a=vector, b=ivar_word, c=entry_byte
    //   msix-bound          a=irq_vector, b=1 (ok flag), c=0
    //   msix-fallback-poll  a=device_id, b=0, c=0
    if (SubEq(e.event, "ivar-programmed"))
    {
        arch::SerialWrite("  vector=");
        WriteHex(e.a);
        arch::SerialWrite(" ivar_word=");
        WriteHex(e.b);
        arch::SerialWrite(" entry_byte=");
        WriteHex(e.c);
        return true;
    }
    if (SubEq(e.event, "msix-bound"))
    {
        arch::SerialWrite("  vector=");
        WriteHex(e.a);
        arch::SerialWrite(" bound=");
        WriteDec(e.b);
        return true;
    }
    if (SubEq(e.event, "msix-fallback-poll"))
    {
        arch::SerialWrite("  device_id=");
        WriteHex(e.a);
        return true;
    }
    return false;
}

bool DecodePeLoader(const CleanroomTraceEntry& e)
{
    if (SubEq(e.event, "imports-resolved"))
    {
        arch::SerialWrite("  image_base=");
        WriteHex(e.a);
        arch::SerialWrite(" resolved=");
        WriteDec(e.b);
        return true;
    }
    if (SubEq(e.event, "import-data-catchall") || SubEq(e.event, "import-fn-catchall"))
    {
        arch::SerialWrite("  image_base=");
        WriteHex(e.a);
        arch::SerialWrite(" iat_addr=");
        WriteHex(e.b);
        arch::SerialWrite(" slot_count=");
        WriteDec(e.c);
        return true;
    }
    if (SubEq(e.event, "import-unresolved-fatal"))
    {
        arch::SerialWrite("  image_base=");
        WriteHex(e.a);
        arch::SerialWrite(" first_thunk=");
        WriteHex(e.b);
        return true;
    }
    return false;
}

bool DecodeXhci(const CleanroomTraceEntry& e)
{
    if (SubEq(e.event, "bulk-cache-hit"))
    {
        arch::SerialWrite("  trb_phys=");
        WriteHex(e.a);
        arch::SerialWrite(" code=");
        WriteHex(e.b);
        arch::SerialWrite(" residual=");
        WriteDec(e.c);
        return true;
    }
    if (SubEq(e.event, "bulk-timeout"))
    {
        arch::SerialWrite("  trb_phys=");
        WriteHex(e.a);
        arch::SerialWrite(" timeout_us=");
        WriteDec(e.b);
        return true;
    }
    return false;
}

} // namespace

void CleanroomTraceWriteDecoded(const CleanroomTraceEntry& e)
{
    bool decoded = false;
    if (SubEq(e.subsystem, "syscall"))
        decoded = DecodeSyscall(e);
    else if (SubEq(e.subsystem, "shell"))
        decoded = DecodeShell(e);
    else if (SubEq(e.subsystem, "wifi"))
        decoded = DecodeWifi(e);
    else if (SubEq(e.subsystem, "fw-loader"))
        decoded = DecodeFwLoader(e);
    else if (SubEq(e.subsystem, "e1000"))
        decoded = DecodeE1000(e);
    else if (SubEq(e.subsystem, "pe-loader"))
        decoded = DecodePeLoader(e);
    else if (SubEq(e.subsystem, "xhci"))
        decoded = DecodeXhci(e);
    if (!decoded)
    {
        arch::SerialWrite("  a=");
        WriteHex(e.a);
        arch::SerialWrite(" b=");
        WriteHex(e.b);
        arch::SerialWrite(" c=");
        WriteHex(e.c);
    }
}

u64 CleanroomTraceHashToken(const char* text)
{
    // FNV-1a 64-bit. The earlier revision of this function used a
    // truncated offset basis (1469598103934665603, missing the
    // trailing digit of the spec-correct value); the values below
    // are the real RFC-style FNV-1a-64 constants so external
    // decoders can use any standard FNV-1a-64 implementation
    // unchanged. Keep tools/cleanroom/decode_hash.py in lockstep.
    constexpr u64 kOffset = 14695981039346656037ull;
    constexpr u64 kPrime = 1099511628211ull;
    u64 h = kOffset;
    if (text == nullptr)
        return h;
    for (u32 i = 0; text[i] != '\0'; ++i)
    {
        h ^= static_cast<u8>(text[i]);
        h *= kPrime;
    }
    return h;
}

} // namespace duetos::core
