#include "crprobe.h"

#include "../arch/x86_64/serial.h"
#include "../net/wifi.h"
#include "cleanroom_trace.h"
#include "firmware_loader.h"
#include "types.h"

namespace duetos::core
{

namespace
{

// Stub Wi-Fi backend. Returns a single synthetic AP for scan and
// accepts every connect / disconnect. The point is to exercise
// wifi::register-ok / scan-ok / connect-ok / disconnect-ok in
// software; nothing here pretends to talk to a real radio.

bool StubWifiScan(void* /*ctx*/, net::WifiScanResult* out, u32 max_results, u32* out_count)
{
    if (out_count != nullptr)
        *out_count = 0;
    if (out == nullptr || max_results < 1)
        return false;
    out[0] = {};
    const char fake[] = "DuetOS-StubAP";
    for (u32 i = 0; fake[i] != '\0' && i < net::kWifiSsidMaxBytes; ++i)
        out[0].ssid[i] = fake[i];
    out[0].rssi_dbm = -55;
    out[0].security = net::WifiSecurity::Wpa2Psk;
    if (out_count != nullptr)
        *out_count = 1;
    return true;
}

bool StubWifiConnect(void* /*ctx*/, const char* /*ssid*/, net::WifiSecurity /*security*/, const char* /*psk*/)
{
    return true;
}

bool StubWifiDisconnect(void* /*ctx*/)
{
    return true;
}

} // namespace

void CrProbeRun()
{
    arch::SerialWrite("[crprobe] driving wifi + fw-loader trace dispatch points\n");

    // wifi::register-ok / register-reject — non-null fn pointers required.
    net::WifiBackendOps ops{};
    ops.scan = StubWifiScan;
    ops.connect = StubWifiConnect;
    ops.disconnect = StubWifiDisconnect;
    ops.ctx = nullptr;
    const bool reg_ok = net::WifiRegisterBackend(0, ops);
    arch::SerialWrite(reg_ok ? "[crprobe] wifi register-ok\n" : "[crprobe] wifi register-rejected\n");

    // wifi::scan-ok — stub returns one fake AP.
    net::WifiScanResult results[net::kWifiMaxScanResults] = {};
    u32 count = 0;
    const bool scan_ok = net::WifiScan(0, results, net::kWifiMaxScanResults, &count);
    (void)scan_ok;
    (void)count;

    // wifi::connect-ok — stub accepts every credential set.
    (void)net::WifiConnect(0, "DuetOS-StubAP", net::WifiSecurity::Wpa2Psk, "stubpassphrase");

    // wifi::disconnect-ok — stub accepts every disconnect.
    (void)net::WifiDisconnect(0);

    // fw-loader::path-attempt — request a vendor blob no backend
    // can satisfy. Loader walks its candidate paths, each miss
    // recording one trace entry.
    FwLoadRequest req{};
    req.vendor = "duetos-synthetic";
    req.basename = "crprobe-stub.fw";
    req.min_bytes = 0;
    req.max_bytes = 0;
    auto r = FwLoad(req);
    (void)r;

    arch::SerialWrite("[crprobe] done — see `crtrace show` for fired events\n");
}

} // namespace duetos::core
