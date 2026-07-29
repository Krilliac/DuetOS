#pragma once

#include "util/types.h"

/*
 * DuetOS — measured boot as a LOCAL tripwire.
 *
 * Measures what actually booted into the TPM's PCRs and answers one
 * question, on this machine, for this machine's owner: HAS THE BOOT
 * CHAIN CHANGED SINCE THE LAST TIME I LOOKED?
 *
 * DETECTION WITHOUT REPORTING. Measurement and attestation are
 * separable and DuetOS implements only the first. There is no code
 * here that signs a PCR set, no code that sends one anywhere, and no
 * API that hands a guest a value derived from the chip's identity.
 * The composite digest below is a function of the FIRMWARE and the
 * KERNEL CONFIGURATION, not of the TPM's endorsement key — two
 * machines with identical firmware and an identical boot command line
 * produce an identical digest, so it cannot single out a machine even
 * if it did leak.
 *
 * That property is load-bearing, not incidental. A "measured boot"
 * that reported to a remote verifier would be the attestation feature
 * this project has declined to build; see the header comment in
 * `drivers/tpm/tpm_wire.h` for the full rule and the condition that
 * would void it.
 *
 * WHAT GETS MEASURED, and into which PCR (TCG convention: 0-7 belong
 * to firmware, 8+ to the OS):
 *   - PCR 10: the kernel's build identity (git hash + branch). Changes
 *             when the kernel binary changes.
 *   - PCR 11: the kernel command line. Changes when someone alters how
 *             the kernel was told to behave, which is the cheapest way
 *             to subvert a machine you have physical access to.
 *
 * The composite digest is SHA-256 over PCR 0-7, 10 and 11, read back
 * FROM THE CHIP, so it covers firmware's own measurements as well as
 * ours. Reading back rather than trusting our own arithmetic is the
 * point: if anything else extended those PCRs, the readback differs.
 *
 * PCR 8 and 9 are deliberately EXCLUDED. GRUB's TPM module measures
 * its own commands into 8 and the files it loads into 9, and those
 * commands include the raw kernel command line — the pinned baseline
 * included. Folding them in would make the digest depend on the
 * baseline, so pinning it would change it and no boot could ever
 * report a match. The cost is that a tampered grub.cfg is not caught
 * by the composite; the kernel command line it produces still is, via
 * PCR 11.
 *
 * Context: kernel, boot path, after TpmInit. No-op with no TPM.
 */

namespace duetos::drivers::tpm
{

/// The PCRs folded into the composite boot digest, in this order.
/// 0-7 are firmware's own measurements; 10 and 11 are ours. 8 and 9
/// are GRUB's and are excluded — see the file comment.
inline constexpr u32 kMeasuredPcrs[] = {0, 1, 2, 3, 4, 5, 6, 7, 10, 11};
inline constexpr u32 kMeasuredPcrCount = sizeof(kMeasuredPcrs) / sizeof(kMeasuredPcrs[0]);

/// Outcome of the tripwire comparison. Deliberately distinguishes "no
/// baseline to compare against" from "compared and matched" — a system
/// that has never been pinned is not the same as one that verified.
enum class BootIntegrity : u8
{
    NoTpm,       // no chip; nothing was measured
    NotMeasured, // chip present but measurement failed
    Unpinned,    // measured, but no baseline was supplied to compare to
    Match,       // measured and identical to the pinned baseline
    Changed,     // measured and DIFFERENT from the pinned baseline
};

/// Extend PCR 8 / 9 with the kernel identity and command line, then
/// compute the composite digest and compare it against a baseline
/// pinned on the kernel command line as `tpm.baseline=<64 hex chars>`.
///
/// The baseline lives on the command line rather than on disk because
/// DuetOS has no writable persistent store yet (see the Persistence
/// item in the roadmap). That is a real constraint, not a placeholder:
/// an operator reads the digest off one trusted boot and pins it, and
/// the tripwire is complete and useful from that point on. When a
/// persistent store lands, it becomes an additional baseline source
/// rather than a redesign.
///
/// GAP: pinning the baseline on the command line only works where
/// editing the boot configuration leaves the boot IMAGE byte-identical,
/// because PCR 4 measures that image - revisit when a writable
/// persistent store lets the baseline live outside the measured set.
/// Under `tools/qemu/run.sh`, `DUETOS_EXTRA_CMDLINE` rebuilds the ISO
/// with the config embedded in the EFI image, so PCR 4 moves with the
/// baseline and no pinned boot there can report Match. A conventional
/// install, whose boot config is a file the loader reads rather than
/// part of the loader binary, does not have that problem.
///
/// Safe to call with a nullptr cmdline and safe with no TPM.
void TpmMeasureBoot(const char* cmdline);

/// Result of the last `TpmMeasureBoot` call.
BootIntegrity TpmBootIntegrity();

/// Copy the composite boot digest computed by `TpmMeasureBoot`. False
/// if no measurement has been taken, in which case `out` is untouched
/// — an unmeasured system reports nothing rather than reporting zeros.
bool TpmBootDigest(u8 out[32]);

/// Human-readable form of `TpmBootIntegrity`, for the shell.
const char* BootIntegrityName(BootIntegrity state);

/// Exercise the composite-digest folding and the baseline comparison
/// against synthetic PCR values. Pure logic; runs with no TPM.
void TpmMeasureSelfTest();

} // namespace duetos::drivers::tpm
