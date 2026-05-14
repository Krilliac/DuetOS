/*
 * DuetOS — secrets-at-rest envelope implementation.
 *
 * See persistence.h for the public contract and envelope layout.
 * Pairs Argon2id (KEK derivation) with ChaCha20-Poly1305 (AEAD on
 * the records). Both primitives are KAT-verified at boot before
 * this layer's own self-test runs.
 */

#include "security/persistence.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "security/argon2id.h"
#include "security/chacha20_poly1305.h"
#include "util/random.h"
#include "util/string.h"
#include "util/types.h"

namespace duetos::security
{

namespace
{

constexpr u8 kMagic[4] = {'D', 'S', 'E', 'C'};
constexpr u32 kKekBytes = kChaCha20KeyBytes; // 32

inline void StoreLE32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

inline u32 LoadLE32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

using duetos::core::StrLen;

// Pack the cleartext header (everything that precedes the
// ciphertext). Returns the number of bytes written
// (= kPersistenceHeaderBytes).
u32 PackHeader(u8 hdr[kPersistenceHeaderBytes], u32 record_count, u32 record_size, const u8 salt[kPersistenceSaltBytes],
               const PersistenceParams& p, const u8 nonce[kPersistenceNonceBytes])
{
    u32 off = 0;
    for (u32 i = 0; i < 4; ++i)
        hdr[off++] = kMagic[i];
    StoreLE32(hdr + off, kPersistenceFormatVersion);
    off += 4;
    StoreLE32(hdr + off, record_count);
    off += 4;
    StoreLE32(hdr + off, record_size);
    off += 4;
    for (u32 i = 0; i < kPersistenceSaltBytes; ++i)
        hdr[off++] = salt[i];
    StoreLE32(hdr + off, p.memory_kib);
    off += 4;
    StoreLE32(hdr + off, p.time_cost);
    off += 4;
    StoreLE32(hdr + off, p.parallelism);
    off += 4;
    StoreLE32(hdr + off, 0); // reserved
    off += 4;
    for (u32 i = 0; i < kPersistenceNonceBytes; ++i)
        hdr[off++] = nonce[i];
    return off;
}

// Inverse: parse header from `in` into output fields.
bool UnpackHeader(const u8* in, u32 in_len, u32* record_count, u32* record_size, u8 salt[kPersistenceSaltBytes],
                  PersistenceParams* p, u8 nonce[kPersistenceNonceBytes])
{
    if (in_len < kPersistenceHeaderBytes)
        return false;
    for (u32 i = 0; i < 4; ++i)
        if (in[i] != kMagic[i])
            return false;
    if (LoadLE32(in + 4) != kPersistenceFormatVersion)
        return false;
    *record_count = LoadLE32(in + 8);
    *record_size = LoadLE32(in + 12);
    for (u32 i = 0; i < kPersistenceSaltBytes; ++i)
        salt[i] = in[16 + i];
    p->memory_kib = LoadLE32(in + 32);
    p->time_cost = LoadLE32(in + 36);
    p->parallelism = LoadLE32(in + 40);
    // in[44..47] = reserved, ignored on read.
    for (u32 i = 0; i < kPersistenceNonceBytes; ++i)
        nonce[i] = in[48 + i];
    return true;
}

bool DeriveKek(const char* password, u32 password_len, const u8 salt[kPersistenceSaltBytes], const PersistenceParams& p,
               u8 kek[kKekBytes])
{
    Argon2idParamsRuntime ap{};
    ap.memory_kib = p.memory_kib;
    ap.time_cost = p.time_cost;
    ap.parallelism = p.parallelism;
    ap.tag_len = kKekBytes;
    return Argon2idDerive(reinterpret_cast<const u8*>(password), password_len, salt, kPersistenceSaltBytes, nullptr, 0,
                          nullptr, 0, ap, kek);
}

} // namespace

u32 PersistenceEncodedSize(u32 record_count, u32 record_size)
{
    return kPersistenceHeaderBytes + record_count * record_size + kPersistenceMacBytes;
}

bool PersistenceEncode(const u8* records, u32 record_count, u32 record_size, const char* password, u32 password_len,
                       const PersistenceParams& kdf_params, u8* out, u32 out_capacity, u32* out_len)
{
    if (records == nullptr || out == nullptr || password == nullptr)
        return false;
    if (record_count == 0 || record_size == 0)
        return false;
    // u32-overflow guard on record_count * record_size.
    if (record_count > 0xFFFFu || record_size > 0xFFFFu)
        return false;
    const u32 payload_bytes = record_count * record_size;
    const u32 total = kPersistenceHeaderBytes + payload_bytes + kPersistenceMacBytes;
    if (out_capacity < total)
        return false;

    u8 salt[kPersistenceSaltBytes];
    duetos::core::RandomFillBytes(salt, kPersistenceSaltBytes);
    u8 nonce[kPersistenceNonceBytes];
    duetos::core::RandomFillBytes(nonce, kPersistenceNonceBytes);

    PackHeader(out, record_count, record_size, salt, kdf_params, nonce);

    u8 kek[kKekBytes];
    if (!DeriveKek(password, password_len, salt, kdf_params, kek))
    {
        KLOG_WARN("persistence", "encode: KEK derivation failed");
        return false;
    }

    u8* ct = out + kPersistenceHeaderBytes;
    u8* mac = ct + payload_bytes;
    ChaCha20Poly1305Encrypt(kek, nonce, out, kPersistenceHeaderBytes, records, payload_bytes, ct, mac);

    // Wipe KEK from stack.
    for (u32 i = 0; i < kKekBytes; ++i)
        kek[i] = 0;

    if (out_len != nullptr)
        *out_len = total;
    return true;
}

bool PersistenceDecode(const u8* in, u32 in_len, const char* password, u32 password_len, u8* records_out,
                       u32 records_out_capacity, u32* records_out_count, u32* record_size_out)
{
    if (in == nullptr || records_out == nullptr || password == nullptr)
        return false;
    u32 record_count = 0, record_size = 0;
    u8 salt[kPersistenceSaltBytes];
    u8 nonce[kPersistenceNonceBytes];
    PersistenceParams p{};
    if (!UnpackHeader(in, in_len, &record_count, &record_size, salt, &p, nonce))
        return false;
    if (record_count == 0 || record_size == 0)
        return false;
    if (record_count > 0xFFFFu || record_size > 0xFFFFu)
        return false;

    const u32 payload_bytes = record_count * record_size;
    const u32 total = kPersistenceHeaderBytes + payload_bytes + kPersistenceMacBytes;
    if (total > in_len)
        return false;
    if (records_out_capacity < payload_bytes)
        return false;

    u8 kek[kKekBytes];
    if (!DeriveKek(password, password_len, salt, p, kek))
    {
        KLOG_WARN("persistence", "decode: KEK derivation failed");
        return false;
    }

    const u8* ct = in + kPersistenceHeaderBytes;
    const u8* mac = ct + payload_bytes;
    const bool ok =
        ChaCha20Poly1305Decrypt(kek, nonce, in, kPersistenceHeaderBytes, ct, payload_bytes, mac, records_out);

    for (u32 i = 0; i < kKekBytes; ++i)
        kek[i] = 0;

    if (!ok)
        return false;
    if (records_out_count != nullptr)
        *records_out_count = record_count;
    if (record_size_out != nullptr)
        *record_size_out = record_size;
    return true;
}

namespace
{

bool BytesEq(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

} // namespace

void PersistenceSelfTest()
{
    arch::SerialWrite("[persistence] self-test: envelope round-trip + tamper rejection\n");

    // 3 records of 24 bytes each = 72 bytes plaintext. Sized to
    // match PasswordHashRecordV2 but the persistence layer itself
    // is content-agnostic — fakes here are fine.
    constexpr u32 kRecCount = 3;
    constexpr u32 kRecSize = 24;
    u8 plaintext[kRecCount * kRecSize];
    for (u32 i = 0; i < kRecCount * kRecSize; ++i)
        plaintext[i] = static_cast<u8>(0xAA ^ i);

    // Small KDF params so the boot self-test stays fast. The
    // production path uses the V2 record's own per-install params.
    PersistenceParams p{};
    p.memory_kib = 32;
    p.time_cost = 2;
    p.parallelism = 1;

    const char* pw = "the right password";
    const u32 pw_len = StrLen(pw);

    const u32 cap = PersistenceEncodedSize(kRecCount, kRecSize);
    u8 envelope[kPersistenceHeaderBytes + kRecCount * kRecSize + kPersistenceMacBytes];
    KASSERT(cap == sizeof(envelope), "security/persistence", "envelope size mismatch (header math broke)");

    u32 written = 0;
    KASSERT(PersistenceEncode(plaintext, kRecCount, kRecSize, pw, pw_len, p, envelope, sizeof(envelope), &written),
            "security/persistence", "encode failed");
    KASSERT(written == sizeof(envelope), "security/persistence", "encode wrote wrong number of bytes");

    // Sanity: ciphertext != plaintext (otherwise the AEAD is a
    // no-op — would catch a regression where we skip the
    // ChaCha20 XOR by mistake).
    bool any_diff = false;
    for (u32 i = 0; i < kRecCount * kRecSize; ++i)
        if (envelope[kPersistenceHeaderBytes + i] != plaintext[i])
            any_diff = true;
    KASSERT(any_diff, "security/persistence", "ciphertext equals plaintext (cipher inactive?)");

    // Round-trip decrypt: must succeed and yield byte-identical bytes.
    u8 recovered[kRecCount * kRecSize];
    u32 got_count = 0, got_size = 0;
    KASSERT(
        PersistenceDecode(envelope, sizeof(envelope), pw, pw_len, recovered, sizeof(recovered), &got_count, &got_size),
        "security/persistence", "decode rejected its own envelope");
    KASSERT(got_count == kRecCount, "security/persistence", "decode returned wrong record_count");
    KASSERT(got_size == kRecSize, "security/persistence", "decode returned wrong record_size");
    KASSERT(BytesEq(recovered, plaintext, sizeof(plaintext)), "security/persistence", "round-trip plaintext mismatch");

    // Tampered MAC.
    {
        u8 tampered[sizeof(envelope)];
        for (u32 i = 0; i < sizeof(envelope); ++i)
            tampered[i] = envelope[i];
        tampered[sizeof(envelope) - 1] ^= 0x01;
        KASSERT(!PersistenceDecode(tampered, sizeof(envelope), pw, pw_len, recovered, sizeof(recovered), &got_count,
                                   &got_size),
                "security/persistence", "tampered MAC accepted");
    }

    // Tampered ciphertext.
    {
        u8 tampered[sizeof(envelope)];
        for (u32 i = 0; i < sizeof(envelope); ++i)
            tampered[i] = envelope[i];
        tampered[kPersistenceHeaderBytes + 4] ^= 0x01;
        KASSERT(!PersistenceDecode(tampered, sizeof(envelope), pw, pw_len, recovered, sizeof(recovered), &got_count,
                                   &got_size),
                "security/persistence", "tampered ciphertext accepted");
    }

    // Tampered header byte (record_count field) — covered by the
    // AEAD's associated-data MAC.
    {
        u8 tampered[sizeof(envelope)];
        for (u32 i = 0; i < sizeof(envelope); ++i)
            tampered[i] = envelope[i];
        tampered[8] ^= 0x01; // first byte of record_count
        KASSERT(!PersistenceDecode(tampered, sizeof(envelope), pw, pw_len, recovered, sizeof(recovered), &got_count,
                                   &got_size),
                "security/persistence", "tampered header accepted");
    }

    // Wrong password.
    {
        const char* wrong = "the wrong password";
        KASSERT(!PersistenceDecode(envelope, sizeof(envelope), wrong, StrLen(wrong), recovered, sizeof(recovered),
                                   &got_count, &got_size),
                "security/persistence", "wrong password accepted");
    }

    // Truncated input.
    {
        KASSERT(!PersistenceDecode(envelope, 10, pw, pw_len, recovered, sizeof(recovered), &got_count, &got_size),
                "security/persistence", "truncated input accepted");
    }

    arch::SerialWrite("[persistence] self-test: PASS\n");
}

} // namespace duetos::security
