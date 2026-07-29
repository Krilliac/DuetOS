// test_tpm_wire.cpp — hosted unit test for the freestanding TPM 2.0
// command/response marshalling.
//
// Covers kernel/drivers/tpm/tpm_wire.h:
//   CommandAllowed        — the sealing-half allow-list, including the
//                           permanently-refused identity-half opcodes
//   Writer / Reader       — big-endian framing and saturating bounds
//   Build*                — byte-exact command encodings
//   ParseResponseHeader   — truncation and short-buffer rejection
//   ParseGetRandom        — TPM2B extraction incl. short reads
//   ParsePcrReadSingle    — TPML_PCR_SELECTION skipping and rejection
//                           of replies that carry the wrong digest count
//
// These run against synthetic buffers rather than a live chip, because
// the encoding is exactly the part a boot on one machine will not
// exercise: byte order, the commandSize back-patch, and the reply
// shapes a hostile or buggy TPM could return. Field layouts are pinned
// to TCG TPM 2.0 Library Parts 2 and 3, rev 1.59.
//
// The allow-list cases are not ordinary coverage — they are the
// executable form of the project's sealing-only rule. If someone adds
// quote signing, this test fails.

#include "host_test_helper.h"

#include "drivers/tpm/tpm_wire.h"

using namespace duetos_host_test;
namespace wire = duetos::drivers::tpm::wire;

using duetos::u16;
using duetos::u32;
using duetos::u8;

namespace
{

u32 BeU32(const u8* p)
{
    return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) | (static_cast<u32>(p[2]) << 8) |
           static_cast<u32>(p[3]);
}

u16 BeU16(const u8* p)
{
    return static_cast<u16>((static_cast<u16>(p[0]) << 8) | p[1]);
}

} // namespace

int main()
{
    // ---------------------------------------------------------------
    // The sealing-only rule, as an executable assertion.
    // ---------------------------------------------------------------
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcQuote));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcCertify));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcCertifyCreation));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcActivateCredential));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcMakeCredential));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcGetTime));
    EXPECT_FALSE(wire::CommandAllowed(wire::kCcGetSessionAuditDigest));

    // An unknown opcode is refused too — the list is an allow-list, not
    // a deny-list, so a command code nobody has thought about yet is
    // rejected by default rather than passed through.
    EXPECT_FALSE(wire::CommandAllowed(0x00000000u));
    EXPECT_FALSE(wire::CommandAllowed(0xFFFFFFFFu));

    EXPECT_TRUE(wire::CommandAllowed(wire::kCcStartup));
    EXPECT_TRUE(wire::CommandAllowed(wire::kCcGetRandom));
    EXPECT_TRUE(wire::CommandAllowed(wire::kCcPcrRead));
    EXPECT_TRUE(wire::CommandAllowed(wire::kCcPcrExtend));
    EXPECT_TRUE(wire::CommandAllowed(wire::kCcUnseal));

    // ---------------------------------------------------------------
    // Writer: big-endian order and saturating overflow
    // ---------------------------------------------------------------
    {
        u8 buffer[8] = {};
        wire::Writer w(buffer, sizeof(buffer));
        w.U32(0x11223344u);
        w.U16(0x5566u);
        w.U8(0x77);
        EXPECT_FALSE(w.Overflowed());
        EXPECT_EQ(w.Length(), 7u);
        EXPECT_EQ(buffer[0], 0x11);
        EXPECT_EQ(buffer[3], 0x44);
        EXPECT_EQ(buffer[4], 0x55);
        EXPECT_EQ(buffer[6], 0x77);

        // One more u16 does not fit; the writer must saturate rather
        // than scribble past the end.
        w.U16(0xAABBu);
        EXPECT_TRUE(w.Overflowed());
    }

    // A builder handed a too-small buffer must report failure as a zero
    // length, never a partially-framed command.
    {
        u8 tiny[4] = {};
        EXPECT_EQ(wire::BuildStartup(tiny, sizeof(tiny), wire::kSuClear), 0u);
    }

    // ---------------------------------------------------------------
    // Reader: bounds and TPM2B handling
    // ---------------------------------------------------------------
    {
        const u8 source[] = {0x00, 0x03, 0xAA, 0xBB, 0xCC};
        wire::Reader r(source, sizeof(source));
        u8 out[4] = {};
        u16 length = 0;
        EXPECT_TRUE(r.Buffer2B(out, sizeof(out), &length));
        EXPECT_EQ(length, 3u);
        EXPECT_EQ(out[0], 0xAA);
        EXPECT_EQ(out[2], 0xCC);
        EXPECT_EQ(r.Remaining(), 0u);
    }
    {
        // A TPM2B claiming more bytes than the buffer holds must fail,
        // not read adjacent memory.
        const u8 source[] = {0x00, 0x10, 0xAA};
        wire::Reader r(source, sizeof(source));
        u8 out[16] = {};
        u16 length = 0;
        EXPECT_FALSE(r.Buffer2B(out, sizeof(out), &length));
        EXPECT_TRUE(r.Overflowed());
    }
    {
        // ...and one that fits the wire but not the destination.
        const u8 source[] = {0x00, 0x04, 0x01, 0x02, 0x03, 0x04};
        wire::Reader r(source, sizeof(source));
        u8 out[2] = {};
        u16 length = 0;
        EXPECT_FALSE(r.Buffer2B(out, sizeof(out), &length));
    }

    // ---------------------------------------------------------------
    // Command encodings, byte for byte
    // ---------------------------------------------------------------
    {
        u8 command[wire::kMaxCommandBytes] = {};
        const u32 length = wire::BuildStartup(command, sizeof(command), wire::kSuClear);
        EXPECT_EQ(length, 12u);
        EXPECT_EQ(BeU16(command), wire::kStNoSessions);
        EXPECT_EQ(BeU32(command + 2), 12u); // commandSize back-patched
        EXPECT_EQ(BeU32(command + 6), wire::kCcStartup);
        EXPECT_EQ(BeU16(command + 10), wire::kSuClear);
    }
    {
        u8 command[wire::kMaxCommandBytes] = {};
        const u32 length = wire::BuildGetRandom(command, sizeof(command), 32);
        EXPECT_EQ(length, 12u);
        EXPECT_EQ(BeU32(command + 6), wire::kCcGetRandom);
        EXPECT_EQ(BeU16(command + 10), 32u);
    }
    {
        // PCR_Read for PCR 3 only: selection bit 3 of the first byte.
        u8 command[wire::kMaxCommandBytes] = {};
        const u32 length = wire::BuildPcrRead(command, sizeof(command), 1u << 3);
        EXPECT_EQ(length, 10u + 4u + 2u + 1u + 3u);
        EXPECT_EQ(BeU32(command + 6), wire::kCcPcrRead);
        EXPECT_EQ(BeU32(command + 10), 1u);               // selection count
        EXPECT_EQ(BeU16(command + 14), wire::kAlgSha256); // hash
        EXPECT_EQ(command[16], 3u);                       // sizeofSelect
        EXPECT_EQ(command[17], 0x08);                     // PCR 3
        EXPECT_EQ(command[18], 0x00);
        EXPECT_EQ(command[19], 0x00);

        // PCR 16 must land in the third selection byte, not the first —
        // this is the packing that a naive shift gets wrong.
        u8 wide[wire::kMaxCommandBytes] = {};
        wire::BuildPcrRead(wide, sizeof(wide), 1u << 16);
        EXPECT_EQ(wide[17], 0x00);
        EXPECT_EQ(wide[18], 0x00);
        EXPECT_EQ(wide[19], 0x01);
    }
    {
        // PCR_Extend carries a session tag and a password auth area.
        u8 digest[32];
        for (u32 i = 0; i < 32; ++i)
            digest[i] = static_cast<u8>(i);

        u8 command[wire::kMaxCommandBytes] = {};
        const u32 length = wire::BuildPcrExtend(command, sizeof(command), 5, digest);
        EXPECT_EQ(BeU16(command), wire::kStSessions);
        EXPECT_EQ(BeU32(command + 6), wire::kCcPcrExtend);
        EXPECT_EQ(BeU32(command + 10), 5u); // pcrHandle == PCR index
        EXPECT_EQ(BeU32(command + 14), 9u); // authorizationSize
        EXPECT_EQ(BeU32(command + 18), wire::kRsPw);
        EXPECT_EQ(BeU32(command + 27), 1u); // TPML_DIGEST_VALUES count
        EXPECT_EQ(BeU16(command + 31), wire::kAlgSha256);
        EXPECT_EQ(command[33], 0x00); // first digest byte
        EXPECT_EQ(command[64], 31u);  // last digest byte
        EXPECT_EQ(length, 65u);
        EXPECT_EQ(BeU32(command + 2), length);
    }

    // ---------------------------------------------------------------
    // Response header validation
    // ---------------------------------------------------------------
    {
        const u8 reply[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00};
        const wire::ResponseHeader header = wire::ParseResponseHeader(reply, sizeof(reply));
        EXPECT_TRUE(header.valid);
        EXPECT_EQ(header.tag, wire::kStNoSessions);
        EXPECT_EQ(header.size, 10u);
        EXPECT_EQ(header.code, wire::kRcSuccess);
    }
    {
        // A reply claiming more bytes than were actually received must
        // not be parsed — that is how a truncated read turns into an
        // out-of-bounds body parse.
        const u8 reply[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00};
        EXPECT_FALSE(wire::ParseResponseHeader(reply, sizeof(reply)).valid);
    }
    {
        // ...as must a reply shorter than the header itself.
        const u8 reply[] = {0x80, 0x01, 0x00};
        EXPECT_FALSE(wire::ParseResponseHeader(reply, sizeof(reply)).valid);
    }
    {
        // A size field smaller than the header is nonsense.
        const u8 reply[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
        EXPECT_FALSE(wire::ParseResponseHeader(reply, sizeof(reply)).valid);
    }

    // ---------------------------------------------------------------
    // GetRandom replies
    // ---------------------------------------------------------------
    {
        const u8 reply[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
        u8 out[8] = {};
        u16 length = 0;
        EXPECT_TRUE(wire::ParseGetRandom(reply, sizeof(reply), out, sizeof(out), &length));
        EXPECT_EQ(length, 4u);
        EXPECT_EQ(out[0], 0xDE);
        EXPECT_EQ(out[3], 0xEF);
    }
    {
        // A TPM-level failure code must not yield bytes the caller then
        // treats as entropy.
        const u8 reply[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00};
        u8 out[8] = {};
        u16 length = 0;
        EXPECT_FALSE(wire::ParseGetRandom(reply, sizeof(reply), out, sizeof(out), &length));
    }

    // ---------------------------------------------------------------
    // PCR_Read replies
    // ---------------------------------------------------------------
    {
        // header(10) | updateCounter(4) | selCount(4) | hash(2)
        // | sizeofSelect(1) | select(3) | digestCount(4) | 2B(2) | 32
        u8 reply[62] = {};
        u32 at = 0;
        const u8 header[] = {0x80, 0x01, 0x00, 0x00, 0x00, 62, 0x00, 0x00, 0x00, 0x00};
        for (unsigned char b : header)
            reply[at++] = b;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x07; // pcrUpdateCounter = 7
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x01; // one selection
        reply[at++] = 0x00;
        reply[at++] = 0x0B; // SHA-256
        reply[at++] = 0x03; // sizeofSelect
        reply[at++] = 0x01;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x01; // one digest
        reply[at++] = 0x00;
        reply[at++] = 0x20; // 32 bytes
        for (u32 i = 0; i < 32; ++i)
            reply[at++] = static_cast<u8>(0xA0 + i);
        EXPECT_EQ(at, 62u);

        u8 digest[32] = {};
        u32 counter = 0;
        EXPECT_TRUE(wire::ParsePcrReadSingle(reply, sizeof(reply), digest, &counter));
        EXPECT_EQ(counter, 7u);
        EXPECT_EQ(digest[0], 0xA0);
        EXPECT_EQ(digest[31], static_cast<u8>(0xA0 + 31));

        // A reply carrying zero digests means the TPM declined the
        // selection; treating that as a successful read of a zero
        // digest would be exactly the "faked reading" this driver
        // refuses to do.
        u8 empty[26] = {};
        for (u32 i = 0; i < 10; ++i)
            empty[i] = header[i];
        empty[5] = 26;
        empty[13] = 0x07;
        empty[17] = 0x01;
        empty[19] = 0x0B;
        empty[20] = 0x03;
        // digestCount stays 0
        u8 unused[32] = {};
        EXPECT_FALSE(wire::ParsePcrReadSingle(empty, sizeof(empty), unused, nullptr));
    }

    return finish_main("tpm_wire");
}
