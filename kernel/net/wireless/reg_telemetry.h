#pragma once

#include "util/types.h"

/*
 * DuetOS — Wi-Fi regulatory / TX-power-cap telemetry, v0.
 *
 * READ-ONLY. Reports the active regulatory domain and the per-band
 * maximum legal TX power (EIRP) from the compiled-in regulatory
 * database (kernel/net/wireless/regdb). It does NOT program any radio
 * TX-power register — exceeding the regulatory/calibrated ceiling
 * overheats the PA/PHY and is illegal, so per the hardware-safety
 * contract (wiki/security/Hardware-Safety.md) TX power is read-only
 * telemetry here; the actual clamp lives in the (future) wireless TX
 * path, which must honour the lesser of this cap and the EEPROM-
 * calibrated max.
 *
 * Unlike the MSR readers this never touches hardware — the regdb is a
 * static table — so it is always available and its self-test runs
 * identically everywhere.
 *
 * Context: kernel.
 */

namespace duetos::net::wireless
{

struct RegTelemetryReading
{
    bool valid;          // regdb reachable + an active domain set
    char country[2];     // active ISO 3166-1 alpha-2 code
    bool band_24_valid;  // a 2.4 GHz rule covers the test channel
    i16 max_eirp_24_dbm; // 2.4 GHz max EIRP (dBm), rounded
    bool band_5_valid;   // a 5 GHz rule covers the test channel
    i16 max_eirp_5_dbm;  // 5 GHz max EIRP (dBm), rounded
    u8 domain_count;     // number of compiled-in domains
};

/// Read the active regulatory domain + per-band TX-power caps. The 2.4
/// GHz cap is sampled at channel 6 (2437 MHz) and the 5 GHz cap at
/// channel 36 (5180 MHz) — representative mid-band channels.
RegTelemetryReading RegTelemetryRead();

/// Sample once + log a one-line summary at boot.
void RegTelemetryProbe();

/// Pure-data self-test: the active domain is non-null with a plausible
/// country code, the channel→freq helpers are correct, and the world/
/// US caps land in the legal range. Panics on mismatch; emits one
/// "[reg-telemetry-selftest] PASS" line.
void RegTelemetrySelfTest();

} // namespace duetos::net::wireless
