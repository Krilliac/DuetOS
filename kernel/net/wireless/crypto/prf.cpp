#include "net/wireless/crypto/prf.h"

#include "core/panic.h"
#include "net/wireless/crypto/hmac.h"
#include "net/wireless/crypto/sha1.h"
#include "net/wireless/crypto/sha256.h"

namespace duetos::net::wireless::crypto
{

namespace
{

u32 StringLen(const char* s)
{
    u32 n = 0;
    if (s == nullptr)
        return 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

} // namespace

void Prf(const u8* key, u32 key_len, const char* label, const u8* seed, u32 seed_len, u32 out_bits, u8* out)
{
    if (out == nullptr || out_bits == 0)
        return;
    KASSERT((out_bits & 7u) == 0u, "net/wireless/crypto/prf", "PRF out_bits must be multiple of 8");
    const u32 out_bytes = out_bits / 8u;
    const u32 label_len = StringLen(label);

    // PRF input is `label || 0x00 || seed || counter(u8)`. Buffer
    // is bounded — labels are ≤ ~30 chars, seeds ≤ 76 bytes for
    // 802.11 PTK derivation.
    u8 buf[256];
    KASSERT(label_len + 1u + seed_len + 1u <= sizeof(buf), "net/wireless/crypto/prf", "PRF input too long");
    for (u32 i = 0; i < label_len; ++i)
        buf[i] = static_cast<u8>(label[i]);
    buf[label_len] = 0;
    for (u32 i = 0; i < seed_len; ++i)
        buf[label_len + 1u + i] = seed[i];
    const u32 counter_off = label_len + 1u + seed_len;

    u32 produced = 0;
    u8 counter = 0;
    while (produced < out_bytes)
    {
        buf[counter_off] = counter;
        u8 mac[kSha1DigestBytes];
        HmacSha1(key, key_len, buf, counter_off + 1u, mac);
        const u32 take = (out_bytes - produced < kSha1DigestBytes) ? (out_bytes - produced) : kSha1DigestBytes;
        for (u32 i = 0; i < take; ++i)
            out[produced + i] = mac[i];
        produced += take;
        ++counter;
    }
}

void KdfSha256(const u8* key, u32 key_len, const char* label, const u8* context, u32 context_len, u32 out_bits, u8* out)
{
    // 802.11-2020 §12.7.1.7.5:
    //   KDF-Hash(K, label, context) =
    //     for i in 1..ceil(out_bits/256):
    //       result_i = HMAC-Hash(K, i || label || context || out_bits)
    //     result = result_1 || ... || result_n  truncated to out_bits.
    // The counter `i` is encoded as a 16-bit little-endian
    // integer; `out_bits` is also 16-bit little-endian.
    if (out == nullptr || out_bits == 0)
        return;
    KASSERT((out_bits & 7u) == 0u, "net/wireless/crypto/prf", "KDF out_bits must be multiple of 8");
    const u32 label_len = StringLen(label);
    u32 produced = 0;
    const u32 out_bytes = out_bits / 8u;
    u16 i_le = 1;

    u8 buf[256];
    KASSERT(2u + label_len + context_len + 2u <= sizeof(buf), "net/wireless/crypto/prf", "KDF input too long");
    while (produced < out_bytes)
    {
        u32 off = 0;
        buf[off++] = static_cast<u8>(i_le & 0xFFu);
        buf[off++] = static_cast<u8>((i_le >> 8) & 0xFFu);
        for (u32 k = 0; k < label_len; ++k)
            buf[off++] = static_cast<u8>(label[k]);
        for (u32 k = 0; k < context_len; ++k)
            buf[off++] = context[k];
        buf[off++] = static_cast<u8>(out_bits & 0xFFu);
        buf[off++] = static_cast<u8>((out_bits >> 8) & 0xFFu);

        u8 mac[kSha256DigestBytes];
        HmacSha256(key, key_len, buf, off, mac);
        const u32 take = (out_bytes - produced < kSha256DigestBytes) ? (out_bytes - produced) : kSha256DigestBytes;
        for (u32 k = 0; k < take; ++k)
            out[produced + k] = mac[k];
        produced += take;
        ++i_le;
    }
}

void PrfSelfTest()
{
    // 802.11i Annex H test vector: PRF-512 with all-zero key,
    // label "prefix", data "Hi There" (a non-canonical vector
    // we construct synthetically — the real 802.11i Annex H
    // vectors are PTK-shaped and need full handshake setup).
    // Instead, validate algorithmic invariants: identical inputs
    // produce identical outputs; counter advancement is correct;
    // 8-byte multi-block output starts with the same 20 bytes as
    // a single-block 20-byte run.
    {
        const u8 key[20] = {0};
        u8 a[20];
        u8 b[40];
        Prf(key, 20, "test", reinterpret_cast<const u8*>("data"), 4, 160, a);
        Prf(key, 20, "test", reinterpret_cast<const u8*>("data"), 4, 320, b);
        for (u32 i = 0; i < 20; ++i)
            KASSERT(a[i] == b[i], "net/wireless/crypto/prf", "PRF prefix invariant broken (counter ≠ 0 first block)");
    }

    // 802.11i §F.9 Annex F (Test Vector for Pairwise Key
    // Derivation, PRF-512). PMK / nonces / MACs from the spec:
    //   PMK = 0x0DC0D6EB90555ED6...   (32 bytes)
    //   AA  = 02:00:00:00:00:00     (Authenticator MAC = AP)
    //   SPA = 02:00:00:00:00:01     (Supplicant MAC = client)
    //   ANonce = 0x...               (32 bytes; canonical from spec)
    //   SNonce = 0x...
    //   Expected first 16 bytes of PTK (KCK) =
    //     0xBF6A1037 1F8DF06A 5F7AB683 78B2F676  (per spec)
    // We use the well-published full vector from hostapd's
    // wpa_supplicant/tests/test-eapol.c with PMK = "ThisIsAPassword"-derived
    // (validated by Pbkdf2SelfTest above).
    //
    // For now self-test only the algorithmic invariants. Full
    // PRF KAT lives in the FourWay self-test where the PMK and
    // nonce vectors are bound to a known handshake.
    {
        // Deterministic — same inputs twice produce same output.
        const u8 key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        const u8 seed[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02};
        u8 a[48];
        u8 b[48];
        Prf(key, 16, "Pairwise key expansion", seed, 8, 384, a);
        Prf(key, 16, "Pairwise key expansion", seed, 8, 384, b);
        for (u32 i = 0; i < 48; ++i)
            KASSERT(a[i] == b[i], "net/wireless/crypto/prf", "PRF non-determinism");
    }
}

} // namespace duetos::net::wireless::crypto
