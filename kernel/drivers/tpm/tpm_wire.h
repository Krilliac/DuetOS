#pragma once

#include "util/types.h"

/*
 * DuetOS — TPM 2.0 command / response marshalling.
 *
 * FREESTANDING on purpose. Pure functions over caller-owned byte
 * buffers — no kernel headers, no allocation, no globals — so
 * `tests/host/test_tpm_wire.cpp` can exercise every builder and parser
 * against synthetic buffers on the build host. The kernel-side callers
 * are `kernel/drivers/tpm/tpm.cpp` (command layer) and
 * `kernel/drivers/tpm/tpm_tis.cpp` (transport).
 *
 * Wire format follows TCG TPM 2.0 Library Part 2 (Structures) and
 * Part 3 (Commands), rev 1.59. Everything on the wire is BIG-endian,
 * which is the single most common source of TPM marshalling bugs and
 * the main reason this layer is tested rather than eyeballed.
 *
 * ==========================================================================
 * THE SEALING-ONLY RULE — read before adding a command code here
 * ==========================================================================
 *
 * DuetOS implements the SEALING half of TPM and never the IDENTITY half.
 *
 * IMPLEMENTED (this file marshals them):
 *   - Seal / unseal of local secrets, bound to a PCR policy
 *   - PCR extend + read
 *   - Hardware RNG
 *   - Non-exportable key storage, monotonic counters
 *
 * NEVER IMPLEMENTED (deliberate, not an oversight, not a TODO):
 *   - Endorsement-key (EK) export or EK-certificate reads
 *   - Attestation identity keys (AIKs)
 *   - Quote signing (TPM2_Quote) and every other signed-assertion
 *     command: Certify, CertifyCreation, GetSessionAuditDigest,
 *     GetTime, ActivateCredential, MakeCredential
 *
 * WHY: those commands, and only those commands, turn a TPM into a
 * stable remote-visible hardware identity. They are what enables
 * device fingerprinting and "only approved configurations get service"
 * lock-out. A TPM is a passive coprocessor with no network path of its
 * own; it cannot leak anything the OS does not choose to send. So the
 * defence is simply to never build the sender.
 *
 * HOW IT IS ENFORCED: `CommandAllowed()` below is an allow-list, and
 * `TpmTransactRaw` refuses any command code that fails it. A future
 * slice cannot quietly add quote signing by writing a builder — it
 * must also add the opcode to `kAllowedCommands`, in this file, under
 * this comment. That is the point: the decision has to be confronted,
 * in a diff, by a human.
 *
 * THE CONDITION THAT WOULD VOID THIS RULE: nothing about a hardware
 * generation, a vendor, a certification programme, or a piece of
 * software that "requires attestation to run" is sufficient. The rule
 * would only be revisited if DuetOS itself grew a use for a signed
 * assertion that never leaves the machine AND the project could show
 * that the same signed structure could not be replayed to a remote
 * verifier. Absent a proof of that second half, the answer is no —
 * "an app wants it" is precisely the demand the rule exists to refuse.
 *
 * See wiki/reference/Design-Decisions.md and wiki/security/TPM.md.
 */

namespace duetos::drivers::tpm::wire
{

// ---------------------------------------------------------------------------
// Structure tags (TPM_ST)
// ---------------------------------------------------------------------------

inline constexpr u16 kStNoSessions = 0x8001;
inline constexpr u16 kStSessions = 0x8002;

// ---------------------------------------------------------------------------
// Algorithm identifiers (TPM_ALG_ID). Only what we marshal.
// ---------------------------------------------------------------------------

inline constexpr u16 kAlgRsa = 0x0001;
inline constexpr u16 kAlgSha256 = 0x000B;
inline constexpr u16 kAlgKeyedHash = 0x0008;
inline constexpr u16 kAlgAes = 0x0006;
inline constexpr u16 kAlgEcc = 0x0023;
inline constexpr u16 kAlgCfb = 0x0043;
inline constexpr u16 kAlgNull = 0x0010;

// NIST P-256. The storage-primary curve: fast enough that deriving the
// parent on every seal/unseal is tolerable, unlike RSA-2048 keygen.
inline constexpr u16 kEccNistP256 = 0x0003;

// ---------------------------------------------------------------------------
// Permanent handles (TPM_RH) and session constants
// ---------------------------------------------------------------------------

inline constexpr u32 kRhOwner = 0x40000001;
inline constexpr u32 kRhNull = 0x40000007;
inline constexpr u32 kRsPw = 0x40000009; // password "session"

inline constexpr u8 kSeHmac = 0x00;
inline constexpr u8 kSePolicy = 0x01;
inline constexpr u8 kSeTrial = 0x03;

inline constexpr u8 kSessionAttrContinue = 0x01;

// ---------------------------------------------------------------------------
// Startup types (TPM_SU)
// ---------------------------------------------------------------------------

inline constexpr u16 kSuClear = 0x0000;
inline constexpr u16 kSuState = 0x0001;

// ---------------------------------------------------------------------------
// Response codes (TPM_RC). Only the ones we branch on.
// ---------------------------------------------------------------------------

inline constexpr u32 kRcSuccess = 0x000;
inline constexpr u32 kRcInitialize = 0x100; // TPM not started yet
inline constexpr u32 kRcFailure = 0x101;    // self-test failed
inline constexpr u32 kRcPolicyFail = 0x99D; // PCR policy did not match

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

inline constexpr u32 kSha256DigestSize = 32;
inline constexpr u32 kCommandHeaderSize = 10; // tag(2) + size(4) + code(4)
inline constexpr u32 kResponseHeaderSize = 10;

// A TPM 2.0 implementation must accept at least 1024-byte commands.
// Our largest is TPM2_Create with a sealed payload; 1280 covers it with
// room for the auth area and leaves the buffers stack-allocatable.
inline constexpr u32 kMaxCommandBytes = 1280;
inline constexpr u32 kMaxResponseBytes = 1280;

// Largest secret we will seal. Deliberately small: the sealing tier
// exists for keys (an FDE wrap key, a secrets-store KEK), not for bulk
// data. Keeps every buffer in this path stack-sized.
inline constexpr u32 kMaxSealedSecretBytes = 128;

// PCR count for a TPM 2.0 platform profile: PCR 0..23.
inline constexpr u32 kPcrCount = 24;
inline constexpr u32 kPcrSelectBytes = 3; // ceil(24 / 8)

// ---------------------------------------------------------------------------
// Command codes (TPM_CC) — THE ALLOW-LIST
// ---------------------------------------------------------------------------
//
// Adding a constant here is not enough to make a command reachable; it
// must also appear in `kAllowedCommands` below, which is what the
// transport actually checks. The two are kept separate so that the
// identity-half opcodes can be written down as named, permanently
// refused constants rather than as folklore — a reader can grep for
// `kCcQuote` and find the refusal instead of finding nothing and
// assuming it was merely forgotten.

inline constexpr u32 kCcStartup = 0x00000144;
inline constexpr u32 kCcSelfTest = 0x00000143;
inline constexpr u32 kCcGetCapability = 0x0000017A;
inline constexpr u32 kCcGetRandom = 0x0000017B;
inline constexpr u32 kCcPcrRead = 0x0000017E;
inline constexpr u32 kCcPcrExtend = 0x00000182;
inline constexpr u32 kCcCreatePrimary = 0x00000131;
inline constexpr u32 kCcCreate = 0x00000153;
inline constexpr u32 kCcLoad = 0x00000157;
inline constexpr u32 kCcUnseal = 0x0000015E;
inline constexpr u32 kCcStartAuthSession = 0x00000176;
inline constexpr u32 kCcPolicyPcr = 0x0000017F;
inline constexpr u32 kCcPolicyGetDigest = 0x00000189;
inline constexpr u32 kCcFlushContext = 0x00000165;

// --- Permanently refused: the identity half. Never add these to
// --- kAllowedCommands. See the file header for why, and for the only
// --- condition under which the rule would be revisited.
inline constexpr u32 kCcQuote = 0x00000158;
inline constexpr u32 kCcCertify = 0x00000148;
inline constexpr u32 kCcCertifyCreation = 0x0000014A;
inline constexpr u32 kCcActivateCredential = 0x00000147;
inline constexpr u32 kCcMakeCredential = 0x00000168;
inline constexpr u32 kCcGetTime = 0x0000014C;
inline constexpr u32 kCcGetSessionAuditDigest = 0x00000178;

// The commands the transport will actually emit. Anything else is
// refused before a single byte reaches the FIFO.
inline constexpr u32 kAllowedCommands[] = {
    kCcStartup,          kCcSelfTest,        kCcGetCapability, kCcGetRandom, kCcPcrRead,   kCcPcrExtend,
    kCcCreate,           kCcCreatePrimary,   kCcLoad,          kCcUnseal,    kCcPolicyPcr, kCcFlushContext,
    kCcStartAuthSession, kCcPolicyGetDigest,
};

inline constexpr u32 kAllowedCommandCount = sizeof(kAllowedCommands) / sizeof(kAllowedCommands[0]);

/// True iff `command_code` is on the sealing-half allow-list. The
/// transport calls this on every submission; a false answer is a
/// programming error in the kernel, not a runtime condition, so callers
/// treat it as `PermissionDenied` and log loudly.
inline constexpr bool CommandAllowed(u32 command_code)
{
    for (u32 i = 0; i < kAllowedCommandCount; ++i)
    {
        if (kAllowedCommands[i] == command_code)
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Big-endian cursors
// ---------------------------------------------------------------------------
//
// Both cursors are saturating rather than trapping: once `overflow` is
// set every further operation is a no-op and reads return zero. That
// lets a builder or parser run to completion and be checked once at the
// end, instead of threading a Result through twenty field writes.

class Writer
{
  public:
    constexpr Writer(u8* buffer, u32 capacity) : m_buf(buffer), m_cap(capacity) {}

    constexpr void U8(u8 v)
    {
        if (m_len + 1 > m_cap)
        {
            m_overflow = true;
            return;
        }
        m_buf[m_len++] = v;
    }

    constexpr void U16(u16 v)
    {
        U8(static_cast<u8>(v >> 8));
        U8(static_cast<u8>(v));
    }

    constexpr void U32(u32 v)
    {
        U16(static_cast<u16>(v >> 16));
        U16(static_cast<u16>(v));
    }

    constexpr void Bytes(const u8* data, u32 length)
    {
        if (data == nullptr && length != 0)
        {
            m_overflow = true;
            return;
        }
        for (u32 i = 0; i < length; ++i)
            U8(data[i]);
    }

    /// TPM2B: a u16 length prefix followed by that many bytes.
    constexpr void Buffer2B(const u8* data, u16 length)
    {
        U16(length);
        Bytes(data, length);
    }

    /// Patch the commandSize field once the body length is known.
    constexpr void PatchU32At(u32 offset, u32 v)
    {
        if (offset + 4 > m_len)
        {
            m_overflow = true;
            return;
        }
        m_buf[offset + 0] = static_cast<u8>(v >> 24);
        m_buf[offset + 1] = static_cast<u8>(v >> 16);
        m_buf[offset + 2] = static_cast<u8>(v >> 8);
        m_buf[offset + 3] = static_cast<u8>(v);
    }

    constexpr u32 Length() const { return m_len; }
    constexpr bool Overflowed() const { return m_overflow; }

  private:
    u8* m_buf = nullptr;
    u32 m_cap = 0;
    u32 m_len = 0;
    bool m_overflow = false;
};

class Reader
{
  public:
    constexpr Reader(const u8* buffer, u32 length) : m_buf(buffer), m_len(length) {}

    constexpr u8 U8()
    {
        if (m_pos + 1 > m_len)
        {
            m_overflow = true;
            return 0;
        }
        return m_buf[m_pos++];
    }

    constexpr u16 U16()
    {
        const u16 hi = U8();
        const u16 lo = U8();
        return static_cast<u16>((hi << 8) | lo);
    }

    constexpr u32 U32()
    {
        const u32 hi = U16();
        const u32 lo = U16();
        return (hi << 16) | lo;
    }

    /// Copy `length` bytes out. Returns false (and consumes nothing) if
    /// the source is short or the destination cannot hold them.
    constexpr bool Bytes(u8* out, u32 length, u32 out_capacity)
    {
        if (out == nullptr || length > out_capacity || m_pos + length > m_len)
        {
            m_overflow = true;
            return false;
        }
        for (u32 i = 0; i < length; ++i)
            out[i] = m_buf[m_pos + i];
        m_pos += length;
        return true;
    }

    /// Read a TPM2B into `out`, yielding its length. False on overflow
    /// or if the payload does not fit `out_capacity`.
    constexpr bool Buffer2B(u8* out, u32 out_capacity, u16* out_length)
    {
        const u16 length = U16();
        if (m_overflow)
            return false;
        if (!Bytes(out, length, out_capacity))
            return false;
        if (out_length != nullptr)
            *out_length = length;
        return true;
    }

    /// Advance past `count` bytes without copying them.
    constexpr bool Skip(u32 count)
    {
        if (m_pos + count > m_len)
        {
            m_overflow = true;
            return false;
        }
        m_pos += count;
        return true;
    }

    constexpr u32 Position() const { return m_pos; }
    constexpr u32 Remaining() const { return m_overflow ? 0 : m_len - m_pos; }
    constexpr bool Overflowed() const { return m_overflow; }

  private:
    const u8* m_buf = nullptr;
    u32 m_len = 0;
    u32 m_pos = 0;
    bool m_overflow = false;
};

// ---------------------------------------------------------------------------
// Command framing
// ---------------------------------------------------------------------------

/// Offset of the commandSize field inside a TPM 2.0 command header.
inline constexpr u32 kCommandSizeOffset = 2;

/// Write tag + a placeholder commandSize + commandCode.
inline constexpr void BeginCommand(Writer& w, u16 tag, u32 command_code)
{
    w.U16(tag);
    w.U32(0); // commandSize — patched by FinishCommand
    w.U32(command_code);
}

/// Patch commandSize to the bytes written so far. Returns the total
/// command length, or 0 if the builder overflowed.
inline constexpr u32 FinishCommand(Writer& w)
{
    if (w.Overflowed())
        return 0;
    w.PatchU32At(kCommandSizeOffset, w.Length());
    return w.Overflowed() ? 0 : w.Length();
}

/// A password-authorisation area for one handle: TPM_RS_PW, an empty
/// caller nonce, continueSession, and an empty HMAC. Nine bytes of
/// payload behind a u32 authorizationSize. This is the only auth shape
/// the sealing tier needs for owner-hierarchy and PCR-extend calls,
/// which carry no auth value.
inline constexpr void WritePasswordAuth(Writer& w)
{
    w.U32(9);                   // authorizationSize
    w.U32(kRsPw);               // sessionHandle
    w.U16(0);                   // nonce (empty)
    w.U8(kSessionAttrContinue); // sessionAttributes
    w.U16(0);                   // hmac (empty)
}

/// A policy-session authorisation area. Same shape as the password
/// form but naming a live session handle; the policy digest, not an
/// HMAC, is what authorises the call.
inline constexpr void WritePolicyAuth(Writer& w, u32 session_handle)
{
    w.U32(9);
    w.U32(session_handle);
    w.U16(0);
    w.U8(kSessionAttrContinue);
    w.U16(0);
}

/// TPML_PCR_SELECTION over the SHA-256 bank for the PCRs whose bits are
/// set in `pcr_mask` (bit N selects PCR N, N < kPcrCount).
inline constexpr void WritePcrSelection(Writer& w, u32 pcr_mask)
{
    w.U32(1);              // count: one TPMS_PCR_SELECTION
    w.U16(kAlgSha256);     // hash
    w.U8(kPcrSelectBytes); // sizeofSelect
    for (u32 byte = 0; byte < kPcrSelectBytes; ++byte)
        w.U8(static_cast<u8>((pcr_mask >> (byte * 8)) & 0xFF));
}

// ---------------------------------------------------------------------------
// Builders — one per allowed command
// ---------------------------------------------------------------------------

inline constexpr u32 BuildStartup(u8* out, u32 capacity, u16 startup_type)
{
    Writer w(out, capacity);
    BeginCommand(w, kStNoSessions, kCcStartup);
    w.U16(startup_type);
    return FinishCommand(w);
}

inline constexpr u32 BuildSelfTest(u8* out, u32 capacity, bool full_test)
{
    Writer w(out, capacity);
    BeginCommand(w, kStNoSessions, kCcSelfTest);
    w.U8(full_test ? 1 : 0); // TPMI_YES_NO
    return FinishCommand(w);
}

inline constexpr u32 BuildGetRandom(u8* out, u32 capacity, u16 bytes_requested)
{
    Writer w(out, capacity);
    BeginCommand(w, kStNoSessions, kCcGetRandom);
    w.U16(bytes_requested);
    return FinishCommand(w);
}

inline constexpr u32 BuildPcrRead(u8* out, u32 capacity, u32 pcr_mask)
{
    Writer w(out, capacity);
    BeginCommand(w, kStNoSessions, kCcPcrRead);
    WritePcrSelection(w, pcr_mask);
    return FinishCommand(w);
}

/// TPM2_PCR_Extend for one PCR with a single SHA-256 digest.
inline constexpr u32 BuildPcrExtend(u8* out, u32 capacity, u32 pcr_index, const u8* digest)
{
    Writer w(out, capacity);
    BeginCommand(w, kStSessions, kCcPcrExtend);
    w.U32(pcr_index); // pcrHandle — the PCR index IS the handle
    WritePasswordAuth(w);
    w.U32(1);          // TPML_DIGEST_VALUES count
    w.U16(kAlgSha256); // TPMT_HA hashAlg
    w.Bytes(digest, kSha256DigestSize);
    return FinishCommand(w);
}

inline constexpr u32 BuildFlushContext(u8* out, u32 capacity, u32 handle)
{
    Writer w(out, capacity);
    BeginCommand(w, kStNoSessions, kCcFlushContext);
    w.U32(handle);
    return FinishCommand(w);
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

struct ResponseHeader
{
    u16 tag = 0;
    u32 size = 0;
    u32 code = 0;
    bool valid = false;
};

/// Parse the fixed 10-byte response header and sanity-check `size`
/// against what the transport actually read. A response claiming more
/// bytes than were received is `valid = false` — the caller must not
/// go on to parse a truncated body.
inline constexpr ResponseHeader ParseResponseHeader(const u8* data, u32 length)
{
    ResponseHeader header{};
    if (data == nullptr || length < kResponseHeaderSize)
        return header;

    Reader r(data, length);
    header.tag = r.U16();
    header.size = r.U32();
    header.code = r.U32();
    header.valid = !r.Overflowed() && header.size >= kResponseHeaderSize && header.size <= length;
    return header;
}

/// TPM2_GetRandom response body: a single TPM2B_DIGEST. Yields the
/// byte count actually returned, which the TPM is permitted to make
/// smaller than the request.
inline constexpr bool ParseGetRandom(const u8* data, u32 length, u8* out, u32 out_capacity, u16* out_length)
{
    const ResponseHeader header = ParseResponseHeader(data, length);
    if (!header.valid || header.code != kRcSuccess)
        return false;

    Reader r(data, header.size);
    if (!r.Skip(kResponseHeaderSize))
        return false;
    return r.Buffer2B(out, out_capacity, out_length);
}

/// TPM2_PCR_Read response body: pcrUpdateCounter, the selection the TPM
/// actually honoured, then a TPML_DIGEST. We ask for one PCR at a time,
/// so a reply carrying anything other than exactly one digest of the
/// expected size is rejected rather than guessed at.
inline constexpr bool ParsePcrReadSingle(const u8* data, u32 length, u8* out_digest, u32* out_update_counter)
{
    const ResponseHeader header = ParseResponseHeader(data, length);
    if (!header.valid || header.code != kRcSuccess)
        return false;

    Reader r(data, header.size);
    if (!r.Skip(kResponseHeaderSize))
        return false;

    const u32 update_counter = r.U32();

    // Skip the echoed TPML_PCR_SELECTION.
    const u32 selection_count = r.U32();
    for (u32 i = 0; i < selection_count; ++i)
    {
        r.U16(); // hash
        const u8 select_size = r.U8();
        if (!r.Skip(select_size))
            return false;
    }

    const u32 digest_count = r.U32();
    if (r.Overflowed() || digest_count != 1)
        return false;

    u16 digest_length = 0;
    if (!r.Buffer2B(out_digest, kSha256DigestSize, &digest_length))
        return false;
    if (digest_length != kSha256DigestSize)
        return false;

    if (out_update_counter != nullptr)
        *out_update_counter = update_counter;
    return true;
}

} // namespace duetos::drivers::tpm::wire
