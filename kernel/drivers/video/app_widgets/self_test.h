#pragma once

namespace duetos::drivers::video::app_widgets
{

/// Boot-time self-test: constructs each concrete widget, drives a
/// few synthetic events, verifies state transitions. Emits
/// `[app-widgets-selftest] PASS` on success or `FAIL <reason>` +
/// KBP_PROBE_V(kBootSelftestFail, 0xD0-0xD3) on failure.
void AppWidgetsSelfTest();

/// Accessor for the Pass D umbrella aggregator.
bool AppWidgetsSelfTestPassed();

} // namespace duetos::drivers::video::app_widgets
