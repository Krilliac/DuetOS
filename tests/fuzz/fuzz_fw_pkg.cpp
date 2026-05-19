// DuetOS — firmware-package envelope parser fuzz harness.
//
// FwPackageParse validates the fixed 160-byte DuetOS firmware
// envelope (magic / version / family / flags / payload length /
// SHA-256 payload digest) wrapping a vendor firmware blob loaded
// off disk — attacker-controlled bytes. The harness also drives
// FwPackageLooksLike (the cheap pre-screen) so both the
// header-shape check and the full validate-with-digest path see
// hostile input. The real crypto/sha256 is linked so the digest
// gate is exercised, not stubbed.

#include "loader/firmware_package.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    const duetos::u8* blob = reinterpret_cast<const duetos::u8*>(data);
    const duetos::u32 n = static_cast<duetos::u32>(size);

    (void)duetos::core::FwPackageLooksLike(blob, n);

    duetos::core::FwPackageParsed parsed{};
    auto r = duetos::core::FwPackageParse(blob, n, &parsed);
    if (r.has_value())
    {
        (void)duetos::core::FwPackageHasFlag(parsed, duetos::core::kFwPackageFlagOpenFirmware);
        (void)duetos::core::FwPackageLoadAllowed(parsed, true);
    }
    return 0;
}
