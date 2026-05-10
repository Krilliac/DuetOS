#pragma once

namespace duetos::subsystems::win32
{

/// Boot self-test for the VirtualAlloc reserve/commit region
/// tracker (T5-01 partial). Drives a flat-buffer mini-region
/// table through reserve / commit / decommit / release to
/// verify the bitmap/state transitions match the production
/// path. Logs `[selftest:vmap]
/// ok; reserve+commit+protect+free` on success.
void Win32VmapSelfTest();

} // namespace duetos::subsystems::win32
