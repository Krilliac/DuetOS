// test_pe_delay_import.cpp — delay-load descriptor walk
// (kernel/loader/pe_delay_import.h).
//
// The delay-import directory is attacker-controlled bytes: a PE
// hands us a table offset and a descriptor count and we walk it.
// Every rejection path here is a path a malformed image must take
// INSTEAD of reaching the binder, so each one is asserted rather
// than assumed:
//
//   - the directory-head bound refuses a wrapping / past-EOF table
//   - a descriptor truncated by end-of-file is Incomplete, not read
//   - the all-zero terminator ends the walk
//   - the VC6 absolute-VA form (dlattrRva clear) is refused
//   - a descriptor missing name/IAT/INT is refused
//   - the walk is capped so a table with no terminator can't spin
//
// Pure header, no kernel state — this is the cheap half of the
// delay-load slice, and the half a fuzz/boot cycle would be a
// clumsy way to exercise.

#include "loader/pe_delay_import.h"

#include "host_test_helper.h"

#include <cstdint>
#include <vector>

using namespace duetos::loader::delayimp;
using duetos::u32;
using duetos::u64;
using duetos::u8;

namespace
{

void PutLe32(std::vector<u8>& buf, u64 off, u32 v)
{
    buf[off + 0] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
}

// Build a table of `n` descriptors followed by an all-zero
// terminator. Every descriptor is well-formed RVA-form by default;
// the caller mutates individual fields afterwards.
std::vector<u8> MakeTable(u32 n)
{
    std::vector<u8> buf((n + 1) * kDelayDescriptorSize, 0);
    for (u32 i = 0; i < n; ++i)
    {
        const u64 base = u64(i) * kDelayDescriptorSize;
        PutLe32(buf, base + 0x00, kDelayAttrRva);
        PutLe32(buf, base + 0x04, 0x1000 + i); // name
        PutLe32(buf, base + 0x08, 0x2000 + i); // hmod
        PutLe32(buf, base + 0x0C, 0x3000 + i); // IAT
        PutLe32(buf, base + 0x10, 0x4000 + i); // INT
    }
    return buf;
}

} // namespace

int main()
{
    // ---- DelayTableInBounds -------------------------------------
    // Happy path: a 64-byte directory inside a 4 KiB file.
    EXPECT_TRUE(DelayTableInBounds(/*tbl_off=*/512, /*dir_size=*/64, /*file_len=*/4096));
    // Exactly flush with EOF is still in bounds.
    EXPECT_TRUE(DelayTableInBounds(4096 - 64, 64, 4096));
    // One byte past EOF is not.
    EXPECT_FALSE(DelayTableInBounds(4096 - 63, 64, 4096));
    // A directory shorter than one descriptor carries no descriptor.
    EXPECT_FALSE(DelayTableInBounds(0, kDelayDescriptorSize - 1, 4096));
    // RvaToFile's miss sentinel must never bracket the buffer.
    EXPECT_FALSE(DelayTableInBounds(~u64(0), 64, 4096));
    // Offset past EOF, regardless of size.
    EXPECT_FALSE(DelayTableInBounds(8192, 64, 4096));
    // The subtractive guard: tbl_off near UINT64_MAX with a size
    // that would wrap `tbl_off + dir_size` back into the buffer.
    EXPECT_FALSE(DelayTableInBounds(~u64(0) - 16, 64, 4096));

    // ---- ReadDelayDescriptor: happy path ------------------------
    {
        std::vector<u8> t = MakeTable(2);
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::Ok);
        EXPECT_EQ(d.attributes, kDelayAttrRva);
        EXPECT_EQ(d.name_rva, 0x1000u);
        EXPECT_EQ(d.hmod_rva, 0x2000u);
        EXPECT_EQ(d.iat_rva, 0x3000u);
        EXPECT_EQ(d.int_rva, 0x4000u);

        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 1, d) == DelayDescStatus::Ok);
        EXPECT_EQ(d.name_rva, 0x1001u);

        // Third slot is the all-zero terminator.
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 2, d) == DelayDescStatus::Terminator);
    }

    // ---- Truncation --------------------------------------------
    {
        std::vector<u8> t = MakeTable(1);
        t.resize(kDelayDescriptorSize + 8); // second descriptor half-present
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::Ok);
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 1, d) == DelayDescStatus::Incomplete);
    }
    {
        // Wrapping table offset: `off + 32` must not fold back into
        // the buffer and hand out attacker-chosen bytes.
        std::vector<u8> t = MakeTable(1);
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), ~u64(0) - 8, 0, d) == DelayDescStatus::Incomplete);
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), ~u64(0), 1, d) == DelayDescStatus::Incomplete);
    }
    {
        // Null buffer is refused, not dereferenced.
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(nullptr, 1024, 0, 0, d) == DelayDescStatus::Incomplete);
    }

    // ---- Form / completeness refusals ---------------------------
    {
        // dlattrRva clear => the VC6 absolute-VA form we do not bind.
        std::vector<u8> t = MakeTable(1);
        PutLe32(t, 0x00, 0);
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::NotRvaForm);
        // Populated anyway so the loader can name what it refused.
        EXPECT_EQ(d.name_rva, 0x1000u);
    }
    {
        // A descriptor whose only non-zero field is grAttrs is NOT
        // the terminator; it is an unbindable descriptor.
        std::vector<u8> t = MakeTable(1);
        PutLe32(t, 0x04, 0); // name
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::MissingTable);
    }
    {
        std::vector<u8> t = MakeTable(1);
        PutLe32(t, 0x0C, 0); // IAT
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::MissingTable);
    }
    {
        std::vector<u8> t = MakeTable(1);
        PutLe32(t, 0x10, 0); // INT
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::MissingTable);
    }
    {
        // A descriptor carrying ONLY a timestamp is non-zero, so it
        // is not the terminator — it must be refused, not bound.
        std::vector<u8> t(kDelayDescriptorSize, 0);
        PutLe32(t, 0x1C, 0xDEADBEEF);
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, 0, d) == DelayDescStatus::NotRvaForm);
    }

    // ---- Walk cap ------------------------------------------------
    {
        // A table with no terminator must stop at the cap rather
        // than run to end-of-file.
        std::vector<u8> t = MakeTable(kMaxDelayDescriptors + 4);
        DelayDescriptor d{};
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, kMaxDelayDescriptors - 1, d) == DelayDescStatus::Ok);
        EXPECT_TRUE(ReadDelayDescriptor(t.data(), t.size(), 0, kMaxDelayDescriptors, d) ==
                    DelayDescStatus::IndexOverflow);
    }

    // ---- Status names are grep-able -----------------------------
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::Ok), "Ok");
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::Terminator), "Terminator");
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::Incomplete), "Incomplete");
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::NotRvaForm), "NotRvaForm");
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::MissingTable), "MissingTable");
    EXPECT_STREQ(DelayDescStatusName(DelayDescStatus::IndexOverflow), "IndexOverflow");

    return duetos_host_test::finish_main("pe_delay_import");
}
