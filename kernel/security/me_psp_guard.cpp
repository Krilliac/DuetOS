#include "security/me_psp_guard.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "net/firewall.h"

namespace duetos::security
{

namespace
{

constinit FencedDevice g_devices[kMaxFencedDevices] = {};
constinit u32 g_count = 0;
constinit u64 g_refused_calls = 0;
constinit u64 g_refused_config_writes = 0;
constinit bool g_init_done = false;
constinit bool g_network_blocks_installed = false;
constinit bool g_activated = false;

constexpr u64 kPageMask = 0xFFFULL;

// Round `phys` down to a 4 KiB page boundary and `bytes` up so
// the stored range covers every page any caller could touch.
void NormalizeRange(u64 phys, u64 bytes, u64& out_base, u64& out_size)
{
    out_base = phys & ~kPageMask;
    const u64 end = phys + bytes;
    const u64 end_aligned = (end + kPageMask) & ~kPageMask;
    out_size = end_aligned - out_base;
}

// Inclusive-vs-exclusive overlap of two half-open ranges
// [a, a+a_len) and [b, b+b_len).
bool RangesOverlap(u64 a, u64 a_len, u64 b, u64 b_len)
{
    if (a_len == 0 || b_len == 0)
        return false;
    const u64 a_end = a + a_len;
    const u64 b_end = b + b_len;
    return a < b_end && b < a_end;
}

// One firewall rule: drop everything matching (dir, proto, dst_port_lo..hi).
// Wildcard src/dst IP so the rule fires on every interface and
// every remote peer.
duetos::net::firewall::Rule MakeAmtDrop(duetos::net::firewall::Direction dir, duetos::net::firewall::Proto proto,
                                        u16 port_lo, u16 port_hi)
{
    using namespace duetos::net::firewall;
    Rule r{};
    r.active = true;
    r.dir = dir;
    r.proto = proto;
    r.src = Ipv4Prefix{duetos::net::Ipv4Address{{0, 0, 0, 0}}, 0};
    r.dst = Ipv4Prefix{duetos::net::Ipv4Address{{0, 0, 0, 0}}, 0};
    r.src_port = PortRange{0, 0xFFFF};
    r.dst_port = PortRange{port_lo, port_hi};
    r.action = Action::Deny;
    r.hits = 0;
    return r;
}

// Snapshot the firewall table and return true if a rule with
// the same (dir, proto, dst_port_lo, dst_port_hi, Deny) already
// exists — so MePspGuardActivate is idempotent across boot
// retries / re-init paths.
bool AmtRuleAlreadyPresent(duetos::net::firewall::Direction dir, duetos::net::firewall::Proto proto, u16 port_lo,
                           u16 port_hi)
{
    using namespace duetos::net::firewall;
    Rule snap[kFwMaxRules];
    const u32 n = FwSnapshot(snap, kFwMaxRules);
    for (u32 i = 0; i < n; ++i)
    {
        if (!snap[i].active)
            continue;
        if (snap[i].dir != dir)
            continue;
        if (snap[i].proto != proto)
            continue;
        if (snap[i].action != Action::Deny)
            continue;
        if (snap[i].dst_port.lo != port_lo)
            continue;
        if (snap[i].dst_port.hi != port_hi)
            continue;
        return true;
    }
    return false;
}

void SerialWriteHexU64(u64 v)
{
    arch::SerialWriteHex(v);
}

void EmitBootSummary()
{
    arch::SerialWrite("[me-psp] fenced=");
    SerialWriteHexU64(g_count);
    arch::SerialWrite(" devices");
    for (u32 i = 0; i < g_count; ++i)
    {
        const auto& d = g_devices[i];
        arch::SerialWrite(" [");
        arch::SerialWrite(CoProcessorTag(d.kind));
        arch::SerialWrite(" vendor=");
        SerialWriteHexU64(d.vendor_id);
        arch::SerialWrite(" device=");
        SerialWriteHexU64(d.device_id);
        arch::SerialWrite(" mmio=");
        SerialWriteHexU64(d.mmio_phys);
        arch::SerialWrite("..");
        SerialWriteHexU64(d.mmio_phys + d.mmio_size);
        arch::SerialWrite("]");
    }
    arch::SerialWrite("\n");
}

} // namespace

const char* CoProcessorTag(CoProcessor c)
{
    switch (c)
    {
    case CoProcessor::None:
        return "none";
    case CoProcessor::IntelMeCsme:
        return "intel-csme";
    case CoProcessor::IntelMeGsc:
        return "intel-gsc";
    case CoProcessor::IntelMeTxe:
        return "intel-txe";
    case CoProcessor::IntelMeSps:
        return "intel-sps";
    case CoProcessor::AmdPspCcp:
        return "amd-psp-ccp";
    case CoProcessor::AmdSmu:
        return "amd-smu";
    }
    return "?";
}

void MePspGuardInit()
{
    for (u32 i = 0; i < kMaxFencedDevices; ++i)
        g_devices[i] = FencedDevice{};
    g_count = 0;
    g_refused_calls = 0;
    g_refused_config_writes = 0;
    g_network_blocks_installed = false;
    g_activated = false;
    g_init_done = true;
}

u32 MePspGuardRegister(const FencedDevice& dev)
{
    if (!g_init_done)
        MePspGuardInit();

    if (g_count >= kMaxFencedDevices)
    {
        // Surface, don't silently drop — if the platform ever grows
        // past the static cap we'd otherwise miss a coprocessor.
        KLOG_WARN("security/me-psp", "fenced-device table full — coprocessor NOT fenced");
        arch::SerialWrite("[me-psp] WARN fenced table full — vendor=");
        SerialWriteHexU64(dev.vendor_id);
        arch::SerialWrite(" device=");
        SerialWriteHexU64(dev.device_id);
        arch::SerialWrite("\n");
        return kMaxFencedDevices;
    }

    FencedDevice copy = dev;
    if (copy.mmio_size != 0)
    {
        u64 base = 0;
        u64 size = 0;
        NormalizeRange(copy.mmio_phys, copy.mmio_size, base, size);
        copy.mmio_phys = base;
        copy.mmio_size = size;
    }
    copy.live = true;

    const u32 idx = g_count;
    g_devices[idx] = copy;
    ++g_count;

    // Loud sentinel: this is a real-world security-relevant event
    // (a privileged coprocessor was detected). Stays at WARN level
    // so it shows up in every default-level boot log.
    arch::SerialWrite("[me-psp] WARN fence registered kind=");
    arch::SerialWrite(CoProcessorTag(copy.kind));
    arch::SerialWrite(" vendor=");
    SerialWriteHexU64(copy.vendor_id);
    arch::SerialWrite(" device=");
    SerialWriteHexU64(copy.device_id);
    arch::SerialWrite(" bdf=");
    SerialWriteHexU64(copy.bus);
    arch::SerialWrite(":");
    SerialWriteHexU64(copy.device);
    arch::SerialWrite(".");
    SerialWriteHexU64(copy.function);
    arch::SerialWrite(" mmio=");
    SerialWriteHexU64(copy.mmio_phys);
    arch::SerialWrite("+");
    SerialWriteHexU64(copy.mmio_size);
    arch::SerialWrite("\n");

    KLOG_WARN("security/me-psp", "privileged coprocessor detected and fenced");
    return idx;
}

u32 MePspGuardCount()
{
    return g_count;
}

const FencedDevice& MePspGuardDevice(u32 index)
{
    KASSERT(index < g_count, "security/me-psp", "MePspGuardDevice index out of range");
    return g_devices[index];
}

bool MePspGuardIsForbiddenMmio(u64 phys, u64 bytes)
{
    if (!g_init_done || g_count == 0 || bytes == 0)
        return false;
    u64 base = 0;
    u64 size = 0;
    NormalizeRange(phys, bytes, base, size);
    for (u32 i = 0; i < g_count; ++i)
    {
        const auto& d = g_devices[i];
        if (!d.live || d.mmio_size == 0)
            continue;
        if (RangesOverlap(base, size, d.mmio_phys, d.mmio_size))
        {
            ++g_refused_calls;
            return true;
        }
    }
    return false;
}

bool MePspGuardIsForbiddenBdf(u8 bus, u8 device, u8 function)
{
    if (!g_init_done || g_count == 0)
        return false;
    for (u32 i = 0; i < g_count; ++i)
    {
        const auto& d = g_devices[i];
        if (!d.live)
            continue;
        if (d.bus == bus && d.device == device && d.function == function)
        {
            ++g_refused_config_writes;
            return true;
        }
    }
    return false;
}

u64 MePspGuardConfigWriteRefusalCount()
{
    return g_refused_config_writes;
}

u32 MePspGuardInstallNetworkBlocks()
{
    using namespace duetos::net::firewall;

    // AMT (Intel Active Management Technology) and the parallel
    // IPMI / RMCP+ surface AMD's DASH equivalents share. The
    // canonical port set:
    //   TCP 16992 — AMT web UI over HTTP
    //   TCP 16993 — AMT web UI over HTTPS
    //   TCP 16994 — AMT redirection / RAS (SOL / IDE-R)
    //   TCP 16995 — AMT redirection over TLS
    //   UDP 623   — RMCP (IPMI 1.5)        — also DMTF ASF
    //   TCP 623   — IPMI session encapsulation
    //   UDP 664   — RMCP+ (IPMI 2.0 secure)
    //   TCP 664   — secure ASF session
    //
    // NOT blocked here:
    //   TCP 5900   — also used by legitimate VNC; blocking would
    //                trip non-AMT workloads. AMT KVM riding on
    //                5900 is a niche profile we surface to the
    //                operator in the wiki rather than break.
    //   TCP 9971   — Intel Mesh Commander. Niche; surface in wiki.
    //
    // We block both Ingress AND Egress for symmetry: blocking
    // egress prevents an OS-side actor from initiating an AMT
    // dial-home; blocking ingress prevents external operators
    // from reaching AMT via the host stack.
    struct Port
    {
        Proto proto;
        u16 port;
    };
    constexpr Port kAmtPorts[] = {
        {Proto::Tcp, 16992}, {Proto::Tcp, 16993}, {Proto::Tcp, 16994}, {Proto::Tcp, 16995},
        {Proto::Udp, 623},   {Proto::Tcp, 623},   {Proto::Udp, 664},   {Proto::Tcp, 664},
    };

    constexpr Direction kDirs[] = {Direction::Ingress, Direction::Egress};

    u32 installed = 0;
    for (const Port& p : kAmtPorts)
    {
        for (Direction dir : kDirs)
        {
            if (AmtRuleAlreadyPresent(dir, p.proto, p.port, p.port))
                continue;
            Rule r = MakeAmtDrop(dir, p.proto, p.port, p.port);
            const u32 slot = FwAdd(r);
            if (slot == kFwMaxRules)
            {
                arch::SerialWrite("[me-psp] WARN firewall full — AMT rule NOT installed for port=");
                SerialWriteHexU64(p.port);
                arch::SerialWrite("\n");
                continue;
            }
            ++installed;
        }
    }
    g_network_blocks_installed = (installed > 0) || g_network_blocks_installed;
    return installed;
}

void MePspGuardActivate()
{
    if (!g_init_done)
        MePspGuardInit();

    const u32 fw_installed = MePspGuardInstallNetworkBlocks();
    g_activated = true;

    arch::SerialWrite("[me-psp] activated fenced=");
    SerialWriteHexU64(g_count);
    arch::SerialWrite(" fw_rules_new=");
    SerialWriteHexU64(fw_installed);
    arch::SerialWrite("\n");

    EmitBootSummary();

    if (g_count == 0)
    {
        KLOG_INFO("security/me-psp", "no privileged coprocessor detected on this platform");
    }
    else
    {
        KLOG_WARN("security/me-psp", "coprocessor(s) detected — host interfaces fenced, AMT ports blocked");
    }
}

u64 MePspGuardRefusalCount()
{
    return g_refused_calls;
}

void MePspGuardSelfTest()
{
    // Drive the policy module through a tight set of asserts. We
    // restore the global state at the end so this is safe to call
    // at boot even on a platform that has live ME/PSP devices.
    const u32 saved_count = g_count;
    const u64 saved_refused = g_refused_calls;

    // 1. Tag lookup table is fully populated for every enumerator.
    auto eq_tag = [](CoProcessor c, char first_char)
    {
        const char* t = CoProcessorTag(c);
        if (t == nullptr || t[0] != first_char)
        {
            arch::SerialWrite("[me-psp-selftest] FAIL tag-mismatch kind=");
            SerialWriteHexU64(static_cast<u64>(c));
            arch::SerialWrite("\n");
            core::PanicWithValue("security/me-psp", "tag lookup mismatch", static_cast<u64>(c));
        }
    };
    eq_tag(CoProcessor::None, 'n');
    eq_tag(CoProcessor::IntelMeCsme, 'i');
    eq_tag(CoProcessor::IntelMeGsc, 'i');
    eq_tag(CoProcessor::IntelMeTxe, 'i');
    eq_tag(CoProcessor::IntelMeSps, 'i');
    eq_tag(CoProcessor::AmdPspCcp, 'a');
    eq_tag(CoProcessor::AmdSmu, 'a');

    // 2. Forbidden-range check.
    //    Insert a synthetic fenced range at a high physical
    //    address that no real BAR could collide with, then
    //    drive overlap / no-overlap / adjacent cases.
    constexpr u64 kSynthBase = 0x0000F00DBA5E0000ULL;
    constexpr u64 kSynthSize = 0x1000ULL;
    if (g_count >= kMaxFencedDevices)
    {
        arch::SerialWrite("[me-psp-selftest] FAIL guard table full at selftest entry\n");
        core::PanicWithValue("security/me-psp", "selftest table full", g_count);
    }
    FencedDevice synth{};
    synth.live = true;
    synth.kind = CoProcessor::IntelMeCsme;
    synth.mmio_phys = kSynthBase;
    synth.mmio_size = kSynthSize;
    g_devices[g_count] = synth;
    const u32 synth_idx = g_count;
    ++g_count;

    auto fail = [](const char* what)
    {
        arch::SerialWrite("[me-psp-selftest] FAIL ");
        arch::SerialWrite(what);
        arch::SerialWrite("\n");
        core::PanicWithValue("security/me-psp", "selftest failure", 0);
    };

    const u64 refused_before = g_refused_calls;
    if (MePspGuardIsForbiddenMmio(kSynthBase, kSynthSize) != true)
        fail("exact-range not refused");
    if (MePspGuardIsForbiddenMmio(kSynthBase + 0x100, 0x10) != true)
        fail("interior not refused");
    if (MePspGuardIsForbiddenMmio(kSynthBase - kSynthSize, kSynthSize) != false)
        fail("non-overlap-low refused incorrectly");
    if (MePspGuardIsForbiddenMmio(kSynthBase + kSynthSize, kSynthSize) != false)
        fail("non-overlap-high refused incorrectly");
    // Adjacent-by-page should overlap because NormalizeRange page-aligns.
    if (MePspGuardIsForbiddenMmio(kSynthBase + kSynthSize - 1, 2) != true)
        fail("byte-spanning overlap not refused");

    if (g_refused_calls < refused_before + 3)
        fail("refusal counter did not increment");

    // 3. Tear synthetic entry down — restore exact pre-selftest state.
    g_devices[synth_idx] = FencedDevice{};
    g_count = saved_count;
    g_refused_calls = saved_refused;

    arch::SerialWrite("[me-psp-selftest] PASS (fenced=");
    SerialWriteHexU64(g_count);
    arch::SerialWrite(" refused=");
    SerialWriteHexU64(g_refused_calls);
    arch::SerialWrite(")\n");
}

} // namespace duetos::security
