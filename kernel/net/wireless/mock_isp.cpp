#include "net/wireless/mock_isp.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "net/stack.h"
#include "net/wifi.h"
#include "net/wireless/test/loopback_driver.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::net::wireless
{

namespace
{

using test::LoopbackDriver;

// One WPA2-PSK network behind one software gateway. The AP side
// is initialised with the router's configured password; a client
// must present the same PSK to complete the 4-way handshake.
constexpr char kSsid[] = "DuetOS-ISP";
constexpr char kRouterPass[] = "DuetOS-ISP-pass";
constexpr u8 kApMac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x10};
constexpr u8 kStaMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x10};
constexpr u8 kChannel = 6;
constexpr u32 kNetIface = 3; // stack iface (0=e1000, 1/2=self-tests)
constexpr u8 kGwIp[4] = {10, 7, 0, 1};
constexpr u8 kLeaseIp[4] = {10, 7, 0, 55};

constinit LoopbackDriver g_drv = {};
constinit bool g_registered = false;
constinit bool g_connected = false;
constinit bool g_pump_started = false;

bool StrEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
}

void PumpThreadEntry(void*)
{
    for (;;)
    {
        if (g_connected && g_drv.netif != nullptr)
            test::LoopbackDriverPump(&g_drv);
        duetos::sched::SchedSleepTicks(1);
    }
}

bool MockScan(void* /*ctx*/, WifiScanResult* out, u32 max_results, u32* out_count)
{
    if (out_count != nullptr)
        *out_count = 0;
    if (out == nullptr || max_results < 1 || !g_registered)
        return false;
    out[0] = {};
    for (u32 i = 0; kSsid[i] != '\0' && i < kWifiSsidMaxBytes; ++i)
        out[0].ssid[i] = kSsid[i];
    out[0].rssi_dbm = -52;
    out[0].security = WifiSecurity::Wpa2Psk;
    if (out_count != nullptr)
        *out_count = 1;
    return true;
}

bool MockConnect(void* /*ctx*/, const char* ssid, WifiSecurity security, const char* psk_or_null)
{
    if (!g_registered || !StrEqual(ssid, kSsid) || security != WifiSecurity::Wpa2Psk)
        return false;
    if (psk_or_null == nullptr || psk_or_null[0] == '\0')
        return false;

    // Fresh attempt: reset handshake state, drive scan + associate
    // + 4-way with the *client-supplied* PSK. A wrong PSK fails the
    // MIC check and never reaches Connected.
    if (g_connected)
    {
        test::LoopbackDriverReset(&g_drv);
        g_drv.netif = nullptr;
        g_connected = false;
    }
    test::LoopbackDriverReset(&g_drv);

    auto dr = test::LoopbackDriverDrive(&g_drv, psk_or_null);
    if (!dr.has_value() || g_drv.wdev == nullptr || g_drv.wdev->op_state != WirelessOpState::Connected)
    {
        arch::SerialWrite("[mock-isp] connect rejected — wrong PSK or handshake failure\n");
        return false;
    }

    auto br = test::LoopbackDriverBindNetif(&g_drv, kNetIface, kGwIp, kLeaseIp);
    if (!br.has_value())
    {
        arch::SerialWrite("[mock-isp] connect: netif bind failed\n");
        return false;
    }
    g_connected = true;

    // Acquire a lease before returning so `wifi status` is online
    // immediately; the pump thread then keeps the link serviced.
    duetos::net::DhcpStart(kNetIface);
    for (u32 round = 0; round < 16 && !duetos::net::DhcpLeaseRead().valid; ++round)
    {
        test::LoopbackDriverPump(&g_drv);
        duetos::sched::SchedYield();
    }

    if (!g_pump_started)
    {
        duetos::sched::SchedCreate(PumpThreadEntry, nullptr, "mock-isp-pump");
        g_pump_started = true;
    }
    arch::SerialWrite("[mock-isp] connected + DHCP over GCMP link\n");
    return true;
}

bool MockDisconnect(void* /*ctx*/)
{
    if (g_connected)
    {
        test::LoopbackDriverReset(&g_drv);
        g_drv.netif = nullptr;
        g_connected = false;
    }
    return true;
}

} // namespace

void MockIspInit()
{
    auto rr = test::LoopbackDriverRegister(&g_drv, kSsid, kRouterPass, kApMac, kStaMac, kChannel);
    if (!rr.has_value())
    {
        arch::SerialWrite("[mock-isp] init: loopback register failed — backend not online\n");
        return;
    }
    g_registered = true;

    WifiBackendOps ops{};
    ops.scan = MockScan;
    ops.connect = MockConnect;
    ops.disconnect = MockDisconnect;
    ops.ctx = nullptr;
    if (!WifiRegisterBackend(/*iface_index=*/0, ops))
    {
        arch::SerialWrite("[mock-isp] init: WifiRegisterBackend rejected\n");
        return;
    }
    arch::SerialWrite("[mock-isp] backend online — SSID \"DuetOS-ISP\" (WPA2-PSK) joinable\n");
}

void MockIspSelfTest()
{
    if (!g_registered)
        return;

    WifiScanResult scan[kWifiMaxScanResults] = {};
    u32 n = 0;
    const bool scanned = WifiScan(0, scan, kWifiMaxScanResults, &n);
    KASSERT(scanned && n >= 1, "net/wireless/mock", "scan did not list the mock SSID");
    KASSERT(StrEqual(scan[0].ssid, kSsid), "net/wireless/mock", "scan SSID mismatch");

    // Wrong PSK must be rejected (no association, no IP).
    const bool bad = WifiConnect(0, kSsid, WifiSecurity::Wpa2Psk, "definitely-wrong");
    KASSERT(!bad, "net/wireless/mock", "connect accepted a wrong PSK");
    (void)WifiDisconnect(0);

    // Correct PSK joins and leases an IP over the encrypted link.
    const bool good = WifiConnect(0, kSsid, WifiSecurity::Wpa2Psk, kRouterPass);
    KASSERT(good, "net/wireless/mock", "connect rejected the correct PSK");
    const auto ip = duetos::net::InterfaceIp(kNetIface);
    KASSERT(ip.octets[0] == kLeaseIp[0] && ip.octets[3] == kLeaseIp[3], "net/wireless/mock",
            "joined but no DHCP lease over the link");

    const bool dc = WifiDisconnect(0);
    KASSERT(dc, "net/wireless/mock", "disconnect failed");

    arch::SerialWrite("[mock-isp] PASS — SSID scannable, WPA2 join + lease, wrong-PSK rejected\n");
}

} // namespace duetos::net::wireless
