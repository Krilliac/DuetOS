#include "drivers/tpm/tpm_tis.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "core/panic.h"
#include "drivers/tpm/tpm_wire.h"
#include "log/klog.h"
#include "mm/paging.h"

namespace duetos::drivers::tpm
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

namespace
{

// --- TIS register offsets within a locality window (TCG PTP §6.4) ---
constexpr u32 kRegAccess = 0x000;    // u8
constexpr u32 kRegIntEnable = 0x008; // u32
constexpr u32 kRegStatus = 0x018;    // u32: sts | burstCount<<8
constexpr u32 kRegDataFifo = 0x024;  // u8
constexpr u32 kRegDidVid = 0xF00;    // u32: vendor<<0 | device<<16
constexpr u32 kRegRid = 0xF04;       // u8

// --- TPM_ACCESS bits ---
constexpr u8 kAccessRequestUse = 0x02;
constexpr u8 kAccessActiveLocality = 0x20;
constexpr u8 kAccessValid = 0x80;

// --- TPM_STS bits (low byte of the status register) ---
//
// TCG PC Client PTP §6.5.2.5. Worth writing out in full because the
// obvious guess — packing them upward from bit 0 — is wrong, and the
// resulting driver reads a plausible status byte and waits forever on
// the wrong bit. stsValid is the TOP bit, not bit 6.
constexpr u8 kStsResponseRetry = 0x02; // bit 1
constexpr u8 kStsSelfTestDone = 0x04;  // bit 2
constexpr u8 kStsExpect = 0x08;        // bit 3
constexpr u8 kStsDataAvail = 0x10;     // bit 4
constexpr u8 kStsGo = 0x20;            // bit 5
constexpr u8 kStsCommandReady = 0x40;  // bit 6
constexpr u8 kStsValid = 0x80;         // bit 7

// TSC cycle bounds, not calibrated delays. The TSC frequency is
// unknown this early, so these are deliberately generous: at 1 GHz the
// short bound is 2 s and at 5 GHz it is 0.4 s. Both are far beyond the
// TIS specification's timeouts (A/B/C/D are 750 ms at worst), so a
// bound that fires means the chip is dead, not slow.
constexpr u64 kShortWaitCycles = 2ULL * 1000ULL * 1000ULL * 1000ULL;
constexpr u64 kLongWaitCycles = 10ULL * 1000ULL * 1000ULL * 1000ULL;

constinit volatile u8* g_tis = nullptr;
constinit bool g_ready = false;

// --- Raw register access. All TIS registers are device memory; the
// --- mapping is UC via mm::MapMmio, so no explicit fencing is needed
// --- beyond the volatile accesses themselves.

u8 Read8(u32 offset)
{
    return *reinterpret_cast<volatile u8*>(g_tis + offset);
}

void Write8(u32 offset, u8 value)
{
    *reinterpret_cast<volatile u8*>(g_tis + offset) = value;
}

u32 Read32(u32 offset)
{
    return *reinterpret_cast<volatile u32*>(g_tis + offset);
}

void Write32(u32 offset, u32 value)
{
    *reinterpret_cast<volatile u32*>(g_tis + offset) = value;
}

void CpuRelax()
{
    asm volatile("pause" ::: "memory");
}

/// burstCount lives in bits 8..23 of TPM_STS. Split out so the
/// self-test can pin the shift/mask without a bus.
constexpr u16 DecodeBurstCount(u32 status_register)
{
    return static_cast<u16>((status_register >> 8) & 0xFFFF);
}

/// Low byte of TPM_STS is the status flag field.
constexpr u8 DecodeStatusFlags(u32 status_register)
{
    return static_cast<u8>(status_register & 0xFF);
}

/// A DID/VID of all-ones (unbacked window) or all-zeros (bus held low)
/// is not a vendor — it is the absence of a responder.
constexpr bool DidVidIsResponder(u32 did_vid)
{
    return did_vid != 0xFFFFFFFFu && did_vid != 0x00000000u;
}

/// Spin until every bit in `mask` is set in TPM_STS's flag byte.
bool WaitStatus(u8 mask, u64 cycle_bound)
{
    const u64 start = arch::TscRead();
    for (;;)
    {
        const u32 status = Read32(kRegStatus);
        if ((DecodeStatusFlags(status) & mask) == mask)
            return true;
        if (arch::TscRead() - start > cycle_bound)
            return false;
        CpuRelax();
    }
}

/// Spin until the chip advertises a non-zero burst count, yielding it.
/// Zero means "no FIFO space right now"; a chip that never advertises
/// space is wedged.
u16 WaitBurstCount()
{
    const u64 start = arch::TscRead();
    for (;;)
    {
        const u32 status = Read32(kRegStatus);
        const u16 burst = DecodeBurstCount(status);
        if (burst != 0)
            return burst;
        if (arch::TscRead() - start > kShortWaitCycles)
            return 0;
        CpuRelax();
    }
}

/// Claim locality 0. Idempotent — if we already hold it, returns
/// immediately.
bool RequestLocality()
{
    const u8 access = Read8(kRegAccess);
    if ((access & (kAccessValid | kAccessActiveLocality)) == (kAccessValid | kAccessActiveLocality))
        return true;

    Write8(kRegAccess, kAccessRequestUse);

    const u64 start = arch::TscRead();
    for (;;)
    {
        const u8 now = Read8(kRegAccess);
        if ((now & (kAccessValid | kAccessActiveLocality)) == (kAccessValid | kAccessActiveLocality))
            return true;
        if (arch::TscRead() - start > kShortWaitCycles)
            return false;
        CpuRelax();
    }
}

/// Put the FIFO back in commandReady. Called on every exit path so a
/// failed transaction cannot wedge the next one.
///
/// An 8-bit write: the TPM_STS control bits all live in the low byte,
/// and a byte write is what every other TIS driver issues, so it is the
/// best-tested path through a chip's decoder.
void ReturnToReady()
{
    Write8(kRegStatus, kStsCommandReady);
}

/// Drive the chip into the Ready state, tolerating the case where it
/// was left mid-transaction.
///
/// This needs two attempts, and the reason is a genuine TIS subtlety
/// rather than defensive padding. Writing commandReady from Idle moves
/// the chip to Ready. But writing it from Reception / Execution /
/// Completion is defined as ABORT: the chip discards the in-flight
/// command and lands in Idle WITHOUT setting commandReady. So when
/// firmware hands over a chip it was still using — which is exactly
/// what OVMF does after its own measurements — the first write only
/// aborts, and a second is required to actually arm it.
bool DriveToReady()
{
    for (u32 attempt = 0; attempt < 2; ++attempt)
    {
        if ((DecodeStatusFlags(Read32(kRegStatus)) & kStsCommandReady) != 0)
            return true;
        ReturnToReady();
        if (WaitStatus(kStsCommandReady, kShortWaitCycles))
            return true;
        KLOG_DEBUG_V("drivers/tpm", "commandReady did not latch; STS reads", Read32(kRegStatus));
    }
    return false;
}

/// Push a framed command into the FIFO. The TIS flow-control rule is
/// that all but the final byte are written while `Expect` is set; the
/// chip clears `Expect` when it has the whole command, so writing the
/// last byte separately lets us verify the chip agreed about the length.
Result<void> WriteCommand(const u8* command, u32 length)
{
    u32 written = 0;
    while (written < length - 1)
    {
        const u16 burst = WaitBurstCount();
        if (burst == 0)
            return Err{ErrorCode::IoError};

        u32 chunk = length - 1 - written;
        if (chunk > burst)
            chunk = burst;

        for (u32 i = 0; i < chunk; ++i)
            Write8(kRegDataFifo, command[written + i]);
        written += chunk;
    }

    // The chip must still be expecting exactly the one remaining byte.
    if (!WaitStatus(kStsValid, kShortWaitCycles))
        return Err{ErrorCode::Timeout};
    if ((DecodeStatusFlags(Read32(kRegStatus)) & kStsExpect) == 0)
        return Err{ErrorCode::IoError};

    Write8(kRegDataFifo, command[length - 1]);

    // ...and must stop expecting once it has it.
    if (!WaitStatus(kStsValid, kShortWaitCycles))
        return Err{ErrorCode::Timeout};
    if ((DecodeStatusFlags(Read32(kRegStatus)) & kStsExpect) != 0)
        return Err{ErrorCode::IoError};

    return {};
}

/// Drain `count` bytes out of the FIFO, honouring burst count.
bool ReadFifo(u8* out, u32 count)
{
    u32 read = 0;
    while (read < count)
    {
        const u16 burst = WaitBurstCount();
        if (burst == 0)
            return false;

        u32 chunk = count - read;
        if (chunk > burst)
            chunk = burst;

        for (u32 i = 0; i < chunk; ++i)
            out[read + i] = Read8(kRegDataFifo);
        read += chunk;
    }
    return true;
}

} // namespace

Result<TisIdentity> TpmTisProbe()
{
    if (g_tis == nullptr)
    {
        void* mapped = mm::MapMmio(kTisPhysBase, kTisLocalityBytes);
        if (mapped == nullptr)
            return Err{ErrorCode::OutOfMemory};
        g_tis = static_cast<volatile u8*>(mapped);
    }

    const u32 did_vid = Read32(kRegDidVid);
    if (!DidVidIsResponder(did_vid))
    {
        // Not an error worth logging at WARN — most machines in the
        // test fleet genuinely have no TPM. The caller prints the
        // one-line present=no.
        return Err{ErrorCode::NoDevice};
    }

    // The register snapshot that localises a bring-up failure on a new
    // machine in one boot: which chip answered, whether we hold
    // locality, and what the status byte says. Debug-gated, so a clean
    // boot stays quiet.
    KLOG_DEBUG_V("drivers/tpm", "probe DID/VID", did_vid);
    KLOG_DEBUG_V("drivers/tpm", "probe ACCESS", Read8(kRegAccess));
    KLOG_DEBUG_V("drivers/tpm", "probe STS", Read32(kRegStatus));

    TisIdentity identity{};
    identity.vendor_id = static_cast<u16>(did_vid & 0xFFFF);
    identity.device_id = static_cast<u16>((did_vid >> 16) & 0xFFFF);
    identity.revision_id = Read8(kRegRid);

    // Interrupts stay masked: this driver polls. Leaving a stale
    // firmware-programmed IRQ enabled would deliver a vector nothing
    // is installed on.
    Write32(kRegIntEnable, 0);

    g_ready = true;
    return identity;
}

bool TpmTisReady()
{
    return g_ready;
}

Result<u32> TpmTisTransact(const u8* command, u32 command_length, u8* response, u32 response_capacity)
{
    if (!g_ready || g_tis == nullptr)
        return Err{ErrorCode::BadState};
    if (command == nullptr || response == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (command_length < wire::kCommandHeaderSize || command_length > wire::kMaxCommandBytes)
        return Err{ErrorCode::InvalidArgument};
    if (response_capacity < wire::kResponseHeaderSize)
        return Err{ErrorCode::BufferTooSmall};

    // The allow-list gate. A command code that is not on the sealing
    // half's list never reaches the bus — see tpm_wire.h for why this
    // exists and what it deliberately refuses.
    const u32 command_code = (static_cast<u32>(command[6]) << 24) | (static_cast<u32>(command[7]) << 16) |
                             (static_cast<u32>(command[8]) << 8) | static_cast<u32>(command[9]);
    if (!wire::CommandAllowed(command_code))
    {
        KLOG_WARN_V("drivers/tpm", "refused a command outside the sealing-half allow-list", command_code);
        return Err{ErrorCode::PermissionDenied};
    }

    if (!RequestLocality())
    {
        KLOG_WARN_V("drivers/tpm", "could not claim TIS locality 0; ACCESS reads", Read8(kRegAccess));
        return Err{ErrorCode::Busy};
    }

    if (!DriveToReady())
    {
        KLOG_WARN_2V("drivers/tpm", "chip never reported commandReady", "sts", Read32(kRegStatus), "access",
                     Read8(kRegAccess));
        ReturnToReady();
        return Err{ErrorCode::NotReady};
    }

    const Result<void> write_result = WriteCommand(command, command_length);
    if (!write_result.has_value())
    {
        KLOG_WARN_2V("drivers/tpm", "command write into the FIFO failed", "sts", Read32(kRegStatus), "len",
                     command_length);
        ReturnToReady();
        return Err{write_result.error()};
    }

    Write8(kRegStatus, kStsGo);

    // A full TPM2_SelfTest or an ECC CreatePrimary can take seconds on
    // a discrete chip, so the response wait gets the long bound.
    if (!WaitStatus(static_cast<u8>(kStsValid | kStsDataAvail), kLongWaitCycles))
    {
        KLOG_WARN_V("drivers/tpm", "no response became available after tpmGo; STS reads", Read32(kRegStatus));
        ReturnToReady();
        return Err{ErrorCode::Timeout};
    }

    if (!ReadFifo(response, wire::kResponseHeaderSize))
    {
        ReturnToReady();
        return Err{ErrorCode::IoError};
    }

    // `wire::ParseResponseHeader` validates responseSize against the
    // bytes already in hand, which at this point is only the header —
    // so it cannot be used here. Read the claimed size directly and
    // range-check it before trusting it as a read length.
    const u32 claimed = (static_cast<u32>(response[2]) << 24) | (static_cast<u32>(response[3]) << 16) |
                        (static_cast<u32>(response[4]) << 8) | static_cast<u32>(response[5]);

    if (claimed < wire::kResponseHeaderSize || claimed > wire::kMaxResponseBytes)
    {
        ReturnToReady();
        return Err{ErrorCode::Corrupt};
    }
    if (claimed > response_capacity)
    {
        ReturnToReady();
        return Err{ErrorCode::Truncated};
    }

    const u32 body = claimed - wire::kResponseHeaderSize;
    if (body != 0 && !ReadFifo(response + wire::kResponseHeaderSize, body))
    {
        ReturnToReady();
        return Err{ErrorCode::IoError};
    }

    ReturnToReady();
    return claimed;
}

void TpmTisSelfTest()
{
    // Pure decode checks — no bus access, so this runs identically on a
    // machine with no TPM and is the one TPM self-test that is always
    // meaningful.
    // Pin the PTP status-bit layout. Packing these upward from bit 0 —
    // the intuitive but wrong guess — yields a driver that reads a
    // perfectly plausible status byte and then waits forever on a bit
    // that means something else. That cost a full bring-up cycle
    // against a live TPM, so it gets a permanent guard.
    KASSERT(kStsResponseRetry == 0x02 && kStsSelfTestDone == 0x04 && kStsExpect == 0x08 && kStsDataAvail == 0x10 &&
                kStsGo == 0x20 && kStsCommandReady == 0x40 && kStsValid == 0x80,
            "drivers/tpm", "TPM_STS bit layout matches TCG PTP 6.5.2.5");

    KASSERT(DecodeBurstCount(0x00ABCD40u) == 0xABCD, "drivers/tpm", "burst count decode");
    KASSERT(DecodeStatusFlags(0x00ABCD40u) == 0x40, "drivers/tpm", "status flag decode");
    KASSERT(DecodeBurstCount(0x00000000u) == 0, "drivers/tpm", "zero burst decode");

    // Absence must not be mistaken for a vendor, in either direction.
    KASSERT(!DidVidIsResponder(0xFFFFFFFFu), "drivers/tpm", "all-ones is not a responder");
    KASSERT(!DidVidIsResponder(0x00000000u), "drivers/tpm", "all-zeros is not a responder");
    KASSERT(DidVidIsResponder(0x00011014u), "drivers/tpm", "a real DID/VID is a responder");

    // The refusal gate is the load-bearing privacy property; assert it
    // here so a boot on any machine proves it, TPM or not.
    KASSERT(!wire::CommandAllowed(wire::kCcQuote), "drivers/tpm", "quote is refused");
    KASSERT(!wire::CommandAllowed(wire::kCcCertify), "drivers/tpm", "certify is refused");
    KASSERT(!wire::CommandAllowed(wire::kCcActivateCredential), "drivers/tpm", "activatecredential is refused");
    KASSERT(!wire::CommandAllowed(wire::kCcGetTime), "drivers/tpm", "gettime is refused");
    KASSERT(wire::CommandAllowed(wire::kCcPcrExtend), "drivers/tpm", "pcr extend is allowed");

    arch::SerialWrite("[tpm-tis-selftest] PASS\n");
}

} // namespace duetos::drivers::tpm
