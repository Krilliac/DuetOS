#include "drivers/tpm/tpm.h"

#include "acpi/acpi.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "crypto/sha256.h"
#include "drivers/tpm/tpm_tis.h"
#include "drivers/tpm/tpm_wire.h"
#include "log/klog.h"
#include "sync/adaptive_mutex.h"
#include "util/random.h"

namespace duetos::drivers::tpm
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

namespace
{

constinit sync::AdaptiveMutex g_tpm_lock{};
constinit TpmIdentity g_identity{};
constinit bool g_present = false;
constinit bool g_initialized = false;

/// Largest single GetRandom request. The TPM is free to return less;
/// 32 bytes is one SHA-256 digest's worth and is what every chip
/// satisfies in one shot.
constexpr u16 kRandomChunk = 32;

/// Bytes pulled at init to seed the kernel entropy pool.
constexpr u32 kSeedBytes = 32;

// --- ACPI TPM2 table (TCG ACPI Specification, "TPM2" signature) ---
//
// Read for one reason: the Start Method field says whether the chip
// speaks FIFO/TIS or CRB. This driver implements FIFO only, so a CRB
// platform must be refused rather than driven with the wrong register
// file. The table is NOT used to locate the registers — the FIFO
// window is architecturally fixed at 0xFED40000.

constexpr u32 kTpm2StartMethodOffset = 48;
constexpr u32 kTpm2MinLength = 52;

// TCG ACPI Specification, "Start Method" field. The two we can drive
// are the FIFO ones: 2 is the TPM 1.2-era TIS interface and 6 is the
// TPM 2.0 PTP FIFO-over-MMIO interface, which is what a discrete
// TPM 2.0 and QEMU's `-device tpm-tis` both report.
//
// Everything else is refused: 1 (ACPI Start) needs an AML control
// method to launch each command rather than a tpmGo register write,
// and 7 / 8 / 11 are the Command Response Buffer interface, which is a
// different register file at a different address. Driving any of them
// with FIFO offsets would be reading noise and calling it a TPM.
constexpr u32 kStartMethodTis12Fifo = 2;
constexpr u32 kStartMethodFifoMmio = 6;

/// Firmware's view of the TPM interface. `absent` means no TPM2 table,
/// which on a machine that does have a TPM just means firmware did not
/// describe it — so it is not by itself a reason to skip the probe.
struct Tpm2TableView
{
    bool present = false;
    u32 start_method = 0;
};

Tpm2TableView ReadAcpiTpm2Table()
{
    Tpm2TableView view{};

    u64 phys = 0;
    u32 length = 0;
    if (!acpi::AcpiFindTablePhys("TPM2", &phys, &length))
        return view;
    if (length < kTpm2MinLength)
    {
        KLOG_WARN_V("drivers/tpm", "ACPI TPM2 table is shorter than the spec minimum", length);
        return view;
    }

    const void* mapped = acpi::AcpiMapTable(phys, length);
    if (mapped == nullptr)
    {
        KLOG_WARN("drivers/tpm", "ACPI TPM2 table found but could not be mapped");
        return view;
    }

    const u8* bytes = static_cast<const u8*>(mapped);
    u8 checksum = 0;
    for (u32 i = 0; i < length; ++i)
        checksum = static_cast<u8>(checksum + bytes[i]);
    if (checksum != 0)
    {
        KLOG_WARN("drivers/tpm", "ACPI TPM2 table failed its checksum; ignoring it");
        return view;
    }

    // Little-endian, like every ACPI field (the BIG-endian rule applies
    // to the TPM wire protocol, not to the table describing it).
    view.start_method = static_cast<u32>(bytes[kTpm2StartMethodOffset]) |
                        (static_cast<u32>(bytes[kTpm2StartMethodOffset + 1]) << 8) |
                        (static_cast<u32>(bytes[kTpm2StartMethodOffset + 2]) << 16) |
                        (static_cast<u32>(bytes[kTpm2StartMethodOffset + 3]) << 24);
    view.present = true;
    return view;
}

/// True if the described interface is one this driver can drive.
bool StartMethodIsFifo(u32 start_method)
{
    return start_method == kStartMethodTis12Fifo || start_method == kStartMethodFifoMmio;
}

/// One command/response round trip. Caller holds `g_tpm_lock`.
///
/// Returns the response length on success. A non-zero TPM response
/// code is surfaced as an error rather than being flattened into the
/// success path — the caller decides whether a given code (e.g.
/// TPM_RC_INITIALIZE) is tolerable.
Result<u32> Transact(const u8* command, u32 command_length, u8* response, u32 response_capacity, u32* out_response_code)
{
    const Result<u32> read = TpmTisTransact(command, command_length, response, response_capacity);
    if (!read.has_value())
        return read;

    const wire::ResponseHeader header = wire::ParseResponseHeader(response, read.value());
    if (!header.valid)
        return Err{ErrorCode::Corrupt};

    if (out_response_code != nullptr)
        *out_response_code = header.code;

    if (header.code != wire::kRcSuccess)
    {
        KLOG_DEBUG_V("drivers/tpm", "command returned a non-success response code", header.code);
        return Err{ErrorCode::IoError};
    }
    return read.value();
}

/// TPM2_Startup(CLEAR). Firmware usually does this before handing off,
/// in which case the chip answers TPM_RC_INITIALIZE ("already
/// started"), which is success for our purposes.
bool StartupOrAlreadyStarted()
{
    u8 command[wire::kMaxCommandBytes];
    u8 response[wire::kMaxResponseBytes];

    const u32 length = wire::BuildStartup(command, sizeof(command), wire::kSuClear);
    if (length == 0)
        return false;

    u32 response_code = 0;
    const Result<u32> result = Transact(command, length, response, sizeof(response), &response_code);
    if (result.has_value())
        return true;

    if (response_code == wire::kRcInitialize)
    {
        KLOG_DEBUG("drivers/tpm", "TPM2_Startup reports the chip was already started by firmware");
        return true;
    }

    // Two distinct failures share this line, so name both: a transport
    // error (the chip never completed the exchange) leaves the response
    // code at zero, whereas a TPM-level refusal carries a real TPM_RC.
    KLOG_WARN_2V("drivers/tpm", "TPM2_Startup failed", "transport", static_cast<u64>(result.error()), "tpm-rc",
                 response_code);
    KLOG_WARN_S("drivers/tpm", "TPM2_Startup transport error", "code", ::duetos::core::ErrorCodeName(result.error()));
    return false;
}

/// Pull entropy from the chip and fold it into the shared kernel pool.
///
/// This CONTRIBUTES to `core::RandomFillBytes`; it does not replace the
/// existing TSC/HPET/RDSEED seeding. `RandomMix` only ever XOR-folds,
/// so even a malicious or broken TPM cannot reduce the quality of the
/// pool — which is the correct trust posture for a vendor black box we
/// did not build and cannot audit.
void SeedKernelEntropy()
{
    u8 seed[kSeedBytes];
    const Result<void> pulled = TpmGetRandom(seed, sizeof(seed));
    if (!pulled.has_value())
    {
        KLOG_WARN("drivers/tpm", "hardware RNG read failed; kernel pool keeps its existing seed");
        return;
    }

    ::duetos::core::RandomMix(seed, sizeof(seed));
    KLOG_INFO_V("drivers/tpm", "mixed hardware RNG bytes into the kernel entropy pool", sizeof(seed));
}

} // namespace

void TpmPcrExtendSoftware(u8 pcr[32], const u8 digest[32])
{
    crypto::Sha256Ctx ctx;
    crypto::Sha256Init(ctx);
    crypto::Sha256Update(ctx, pcr, wire::kSha256DigestSize);
    crypto::Sha256Update(ctx, digest, wire::kSha256DigestSize);
    crypto::Sha256Final(ctx, pcr);
}

bool TpmPresent()
{
    return g_present;
}

TpmIdentity TpmGetIdentity()
{
    return g_present ? g_identity : TpmIdentity{};
}

Result<void> TpmGetRandom(u8* out, u32 length)
{
    if (out == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (!TpmTisReady())
        return Err{ErrorCode::NoDevice};

    sync::AdaptiveMutexLock(g_tpm_lock);

    u8 command[wire::kMaxCommandBytes];
    u8 response[wire::kMaxResponseBytes];
    u8 chunk[kRandomChunk];

    u32 filled = 0;
    u32 barren_rounds = 0;
    Result<void> outcome{};

    while (filled < length)
    {
        u32 want = length - filled;
        if (want > kRandomChunk)
            want = kRandomChunk;

        const u32 command_length = wire::BuildGetRandom(command, sizeof(command), static_cast<u16>(want));
        if (command_length == 0)
        {
            outcome = Err{ErrorCode::InvalidArgument};
            break;
        }

        const Result<u32> read = Transact(command, command_length, response, sizeof(response), nullptr);
        if (!read.has_value())
        {
            outcome = Err{read.error()};
            break;
        }

        u16 got = 0;
        if (!wire::ParseGetRandom(response, read.value(), chunk, sizeof(chunk), &got))
        {
            outcome = Err{ErrorCode::Corrupt};
            break;
        }

        // A chip that keeps answering "zero bytes" is not going to
        // start; two in a row ends it rather than spinning forever.
        if (got == 0)
        {
            if (++barren_rounds >= 2)
            {
                outcome = Err{ErrorCode::IoError};
                break;
            }
            continue;
        }
        barren_rounds = 0;

        for (u16 i = 0; i < got && filled < length; ++i)
            out[filled++] = chunk[i];
    }

    sync::AdaptiveMutexUnlock(g_tpm_lock);
    return outcome;
}

Result<void> TpmPcrRead(u32 index, u8 out_digest[32])
{
    if (out_digest == nullptr || index >= wire::kPcrCount)
        return Err{ErrorCode::InvalidArgument};
    if (!TpmTisReady())
        return Err{ErrorCode::NoDevice};

    sync::AdaptiveMutexLock(g_tpm_lock);

    u8 command[wire::kMaxCommandBytes];
    u8 response[wire::kMaxResponseBytes];

    Result<void> outcome{};
    const u32 command_length = wire::BuildPcrRead(command, sizeof(command), 1u << index);
    if (command_length == 0)
    {
        outcome = Err{ErrorCode::InvalidArgument};
    }
    else
    {
        const Result<u32> read = Transact(command, command_length, response, sizeof(response), nullptr);
        if (!read.has_value())
            outcome = Err{read.error()};
        else if (!wire::ParsePcrReadSingle(response, read.value(), out_digest, nullptr))
            outcome = Err{ErrorCode::Corrupt};
    }

    sync::AdaptiveMutexUnlock(g_tpm_lock);
    return outcome;
}

Result<void> TpmPcrExtend(u32 index, const u8 digest[32])
{
    if (digest == nullptr || index >= wire::kPcrCount)
        return Err{ErrorCode::InvalidArgument};
    if (!TpmTisReady())
        return Err{ErrorCode::NoDevice};

    sync::AdaptiveMutexLock(g_tpm_lock);

    u8 command[wire::kMaxCommandBytes];
    u8 response[wire::kMaxResponseBytes];

    Result<void> outcome{};
    const u32 command_length = wire::BuildPcrExtend(command, sizeof(command), index, digest);
    if (command_length == 0)
    {
        outcome = Err{ErrorCode::InvalidArgument};
    }
    else
    {
        const Result<u32> written = Transact(command, command_length, response, sizeof(response), nullptr);
        if (!written.has_value())
            outcome = Err{written.error()};
    }

    sync::AdaptiveMutexUnlock(g_tpm_lock);
    return outcome;
}

void TpmInit()
{
    if (g_initialized)
        return;
    g_initialized = true;

    // If firmware describes the TPM, honour what it says about the
    // interface. A CRB platform has a different register file, and
    // poking the FIFO offsets there would be reading noise and calling
    // it a TPM — exactly the failure mode this driver refuses.
    const Tpm2TableView table = ReadAcpiTpm2Table();
    if (table.present && !StartMethodIsFifo(table.start_method))
    {
        // GAP: CRB (start method 7/8/11) and ACPI Start (1) are
        // unimplemented - revisit when a target machine reports one.
        // Modern fTPM platforms are the likely first case.
        KLOG_WARN_V("drivers/tpm", "ACPI reports a non-FIFO TPM interface; driver stands down", table.start_method);
        arch::SerialWrite("[tpm] present=no (ACPI reports a non-FIFO interface; FIFO driver only)\n");
        return;
    }

    const Result<TisIdentity> probe = TpmTisProbe();
    if (!probe.has_value())
    {
        // Absent is the common, expected case. Say so plainly and do
        // not leave any state that could later read as "present".
        arch::SerialWrite("[tpm] present=no (no TIS responder at 0xFED40000)\n");
        return;
    }

    g_identity.vendor_id = probe.value().vendor_id;
    g_identity.device_id = probe.value().device_id;
    g_identity.revision_id = probe.value().revision_id;

    if (!StartupOrAlreadyStarted())
    {
        arch::SerialWrite("[tpm] present=no (TIS responded but TPM2_Startup failed)\n");
        return;
    }

    g_identity.started = true;
    g_present = true;

    KLOG_INFO_2V("drivers/tpm", "TPM 2.0 present", "vendor", g_identity.vendor_id, "device", g_identity.device_id);
    arch::SerialWrite("[tpm] present=yes\n");

    SeedKernelEntropy();
}

void TpmSelfTest()
{
    // Always-meaningful half: the marshalling and the refusal gate.
    TpmTisSelfTest();

    // Software PCR extend must match the TPM's rule exactly, or the
    // measured-boot tripwire would compare against a wrong expectation.
    // Extending an all-zero PCR with an all-zero digest has a known
    // answer: SHA-256 of 64 zero bytes.
    u8 pcr[32] = {};
    const u8 zero_digest[32] = {};
    TpmPcrExtendSoftware(pcr, zero_digest);

    u8 expected[32];
    const u8 sixty_four_zeros[64] = {};
    crypto::Sha256Hash(sixty_four_zeros, sizeof(sixty_four_zeros), expected);

    for (u32 i = 0; i < 32; ++i)
        KASSERT(pcr[i] == expected[i], "drivers/tpm", "software PCR extend matches SHA256(old||new)");

    if (!g_present)
    {
        // Say which half ran. A bare PASS here would be read as
        // evidence about hardware that is not present.
        arch::SerialWrite("[tpm-selftest] PASS (wire only, no TPM present)\n");
        return;
    }

    // Live half: prove the chip actually answers, and that two RNG
    // reads differ (a chip stuck returning a constant is broken in a
    // way a single read cannot see).
    u8 first[16] = {};
    u8 second[16] = {};
    const bool got_first = TpmGetRandom(first, sizeof(first)).has_value();
    const bool got_second = TpmGetRandom(second, sizeof(second)).has_value();
    KASSERT(got_first && got_second, "drivers/tpm", "hardware RNG answered twice");

    bool differ = false;
    for (u32 i = 0; i < sizeof(first); ++i)
    {
        if (first[i] != second[i])
        {
            differ = true;
            break;
        }
    }
    KASSERT(differ, "drivers/tpm", "hardware RNG is not returning a constant");

    u8 pcr0[32] = {};
    KASSERT(TpmPcrRead(0, pcr0).has_value(), "drivers/tpm", "PCR 0 read");

    arch::SerialWrite("[tpm-selftest] PASS (live: rng + pcr read)\n");
}

} // namespace duetos::drivers::tpm
