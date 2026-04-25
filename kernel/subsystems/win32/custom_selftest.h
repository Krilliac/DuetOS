#pragma once

namespace duetos::subsystems::win32::custom
{

/// One-shot kernel self-test for the Win32 custom-diagnostics
/// suite. Synthesises a fake Process, drives every recorded hook
/// (flight recorder, handle provenance, error provenance,
/// quarantine, deadlock detect, contention, strict-RWX policy
/// query), then dumps the result to serial. Lets the user see
/// concrete data flowing through the diagnostic surfaces without
/// having to wait for a real Win32 PE to run end-to-end.
///
/// Idempotent — call once from `kernel_main` after the runtime
/// invariant checker landing point. Allocates + frees its
/// scratch state inline; leaves no kernel-heap residue.
void Win32CustomSelfTest();

} // namespace duetos::subsystems::win32::custom
