#include "net/wireless/gcmp.h"

#include "arch/x86_64/serial.h"
#include "crypto/aes_gcm.h"

namespace duetos::net::wireless
{

namespace
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

// GCMP / CCMP header byte layout (IEEE 802.11-2020 §12.5.5.2):
//   [0]=PN0 [1]=PN1 [2]=Rsvd(0) [3]=KeyId byte
//   [4]=PN2 [5]=PN3 [6]=PN4 [7]=PN5
// KeyId byte: bit5 ExtIV=1, bits6..7 = key id (we always use 0).
constexpr u8 kKeyIdByte = 0x20;

void WriteGcmpHeader(u8* h, u64 pn)
{
    h[0] = static_cast<u8>(pn & 0xFF);
    h[1] = static_cast<u8>((pn >> 8) & 0xFF);
    h[2] = 0x00;
    h[3] = kKeyIdByte;
    h[4] = static_cast<u8>((pn >> 16) & 0xFF);
    h[5] = static_cast<u8>((pn >> 24) & 0xFF);
    h[6] = static_cast<u8>((pn >> 32) & 0xFF);
    h[7] = static_cast<u8>((pn >> 40) & 0xFF);
}

u64 ReadGcmpHeaderPn(const u8* h)
{
    return static_cast<u64>(h[0]) | (static_cast<u64>(h[1]) << 8) | (static_cast<u64>(h[4]) << 16) |
           (static_cast<u64>(h[5]) << 24) | (static_cast<u64>(h[6]) << 32) | (static_cast<u64>(h[7]) << 40);
}

// GCM IV = A2 (transmitter MAC, 6) || PN (48-bit, MSByte first).
void BuildNonce(const u8 ta[6], u64 pn, u8 nonce[crypto::kGcmIvBytes])
{
    for (u32 i = 0; i < 6; ++i)
        nonce[i] = ta[i];
    nonce[6] = static_cast<u8>((pn >> 40) & 0xFF);
    nonce[7] = static_cast<u8>((pn >> 32) & 0xFF);
    nonce[8] = static_cast<u8>((pn >> 24) & 0xFF);
    nonce[9] = static_cast<u8>((pn >> 16) & 0xFF);
    nonce[10] = static_cast<u8>((pn >> 8) & 0xFF);
    nonce[11] = static_cast<u8>(pn & 0xFF);
}

} // namespace

Result<void> GcmpProtect(const u8 tk[kGcmpTkBytes], const u8 ta[6], u64 pn, const u8* aad, u32 aad_len, const u8* pt,
                         u32 pt_len, u8* out, u32 out_cap, u32* out_len)
{
    if (tk == nullptr || ta == nullptr || pt == nullptr || out == nullptr || out_len == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (pn == 0 || pn > 0xFFFFFFFFFFFFULL)
        return Err{ErrorCode::InvalidArgument};

    const u32 need = kGcmpHeaderBytes + pt_len + kGcmpMicBytes;
    if (out_cap < need)
        return Err{ErrorCode::BufferTooSmall};

    WriteGcmpHeader(out, pn);

    u8 nonce[crypto::kGcmIvBytes];
    BuildNonce(ta, pn, nonce);

    u8* ct = out + kGcmpHeaderBytes;
    u8* tag = ct + pt_len;
    if (!crypto::AesGcm128Encrypt(tk, nonce, aad, aad_len, pt, pt_len, ct, tag))
        return Err{ErrorCode::IoError};

    *out_len = need;
    return Result<void>{};
}

Result<void> GcmpUnprotect(const u8 tk[kGcmpTkBytes], const u8 ta[6], const u8* aad, u32 aad_len, const u8* in,
                           u32 in_len, u64* out_pn, u8* pt_out, u32 pt_cap, u32* pt_len)
{
    if (tk == nullptr || ta == nullptr || in == nullptr || out_pn == nullptr || pt_out == nullptr || pt_len == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (in_len < kGcmpHeaderBytes + kGcmpMicBytes)
        return Err{ErrorCode::Corrupt};
    if ((in[3] & 0x20) == 0) // ExtIV bit must be set for GCMP/CCMP
        return Err{ErrorCode::Corrupt};

    const u32 ct_len = in_len - kGcmpHeaderBytes - kGcmpMicBytes;
    if (pt_cap < ct_len)
        return Err{ErrorCode::BufferTooSmall};

    const u64 pn = ReadGcmpHeaderPn(in);
    u8 nonce[crypto::kGcmIvBytes];
    BuildNonce(ta, pn, nonce);

    const u8* ct = in + kGcmpHeaderBytes;
    const u8* tag = ct + ct_len;
    if (!crypto::AesGcm128Decrypt(tk, nonce, aad, aad_len, ct, ct_len, tag, pt_out))
        return Err{ErrorCode::Corrupt};

    *out_pn = pn;
    *pt_len = ct_len;
    return Result<void>{};
}

void GcmpSelfTest()
{
    const u8 tk[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F};
    const u8 ta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const u8 aad[24] = {0x08, 0x42, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 0, 0};
    const u8 msg[21] = {'D', 'u', 'e', 't', 'O', 'S', '-', 'g', 'c', 'm', 'p',
                        '-', 'd', 'a', 't', 'a', '-', 'p', 'l', 'n', '!'};

    u8 prot[64];
    u32 prot_len = 0;
    auto pr = GcmpProtect(tk, ta, /*pn=*/1, aad, sizeof(aad), msg, sizeof(msg), prot, sizeof(prot), &prot_len);
    if (!pr.has_value() || prot_len != sizeof(msg) + kGcmpOverheadBytes)
    {
        arch::SerialWrite("[wifi-gcmp] FAIL — protect did not produce expected length\n");
        return;
    }

    // Ciphertext must differ from plaintext (real confidentiality).
    bool differs = false;
    for (u32 i = 0; i < sizeof(msg); ++i)
        if (prot[kGcmpHeaderBytes + i] != msg[i])
            differs = true;
    if (!differs)
    {
        arch::SerialWrite("[wifi-gcmp] FAIL — ciphertext equals plaintext\n");
        return;
    }

    u8 rec[64];
    u32 rec_len = 0;
    u64 rec_pn = 0;
    auto ur = GcmpUnprotect(tk, ta, aad, sizeof(aad), prot, prot_len, &rec_pn, rec, sizeof(rec), &rec_len);
    if (!ur.has_value() || rec_len != sizeof(msg) || rec_pn != 1)
    {
        arch::SerialWrite("[wifi-gcmp] FAIL — unprotect round-trip mismatch\n");
        return;
    }
    for (u32 i = 0; i < sizeof(msg); ++i)
    {
        if (rec[i] != msg[i])
        {
            arch::SerialWrite("[wifi-gcmp] FAIL — recovered plaintext corrupted\n");
            return;
        }
    }

    // A single tampered ciphertext byte must fail the tag verify.
    prot[kGcmpHeaderBytes + 3] ^= 0x40;
    auto tr = GcmpUnprotect(tk, ta, aad, sizeof(aad), prot, prot_len, &rec_pn, rec, sizeof(rec), &rec_len);
    if (tr.has_value())
    {
        arch::SerialWrite("[wifi-gcmp] FAIL — tampered frame accepted\n");
        return;
    }

    arch::SerialWrite("[wifi-gcmp] PASS — GCMP-128 protect/unprotect + tamper-reject\n");
}

} // namespace duetos::net::wireless
