#pragma once

namespace duetos::subsystems::win32
{

/// Boot self-test for the kernel-resident APC queue
/// (T8-02). Drives a stand-in Process through the queue/drain/
/// isolation/capacity round-trips. Logs `[selftest:apc] ok;
/// queue+drain+isolation+capacity` on success.
void ApcSelfTest();

} // namespace duetos::subsystems::win32
