#pragma once

namespace duetos::subsystems::win32
{

/// Boot self-test for the Win32 multi-heap allocator (T5-02).
/// Drives a flat-buffer mini-allocator with the same first-fit
/// + split + LIFO-reuse contract the production walker
/// implements. Logs `[selftest:w32-heap] ok; ...` on success.
void Win32HeapSelfTest();

} // namespace duetos::subsystems::win32
