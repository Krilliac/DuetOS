#include "test_main.h"
#include "multiboot2.h"
#include <cstring>
#include <vector>

using duetos::vmm::BuildMultiboot2Info;
using duetos::vmm::Mb2Params;

static const uint8_t* FindTag(const std::vector<uint8_t>& b, uint32_t type, uint32_t& sz)
{
    size_t off = 8;
    while (off + 8 <= b.size())
    {
        uint32_t t, s;
        std::memcpy(&t, &b[off], 4);
        std::memcpy(&s, &b[off + 4], 4);
        if (t == 0) return nullptr;
        if (t == type) { sz = s; return &b[off]; }
        off += (s + 7) & ~size_t(7);
    }
    return nullptr;
}

// Walk the mmap tag (type 6) and collect all entries as {base,len,type}.
struct MmapEntry { uint64_t base, len; uint32_t type; };
static std::vector<MmapEntry> ParseMmap(const std::vector<uint8_t>& b)
{
    uint32_t sz = 0;
    const uint8_t* tag = FindTag(b, 6, sz);
    std::vector<MmapEntry> out;
    if (!tag) return out;
    // tag+0=type(4), tag+4=size(4), tag+8=entry_size(4), tag+12=entry_version(4)
    // entries start at tag+16
    uint32_t entSz = 0;
    std::memcpy(&entSz, tag + 8, 4);
    const uint8_t* p   = tag + 16;
    const uint8_t* end = tag + sz;
    while (p + entSz <= end)
    {
        MmapEntry e{};
        std::memcpy(&e.base, p,      8);
        std::memcpy(&e.len,  p + 8,  8);
        std::memcpy(&e.type, p + 16, 4);
        out.push_back(e);
        p += entSz;
    }
    return out;
}

TEST(mb2_emits_framebuffer_tag_when_fb_set)
{
    Mb2Params p;
    p.cmdline     = "boot=desktop";
    p.ramBytes    = 512ull * 1024 * 1024;
    p.reservedEnd = 0x200000;
    p.fbAddr      = 0x1F000000;
    p.fbWidth     = 1280;
    p.fbHeight    = 1024;
    p.fbPitch     = 1280 * 4;
    p.fbBpp       = 32;

    auto blob = BuildMultiboot2Info(p);
    uint32_t sz = 0;
    const uint8_t* tag = FindTag(blob, 8, sz);
    CHECK(tag != nullptr);
    CHECK_EQ(sz, 38u);
    uint64_t addr;
    uint32_t pitch, w, h;
    std::memcpy(&addr,  tag + 8,  8);
    std::memcpy(&pitch, tag + 16, 4);
    std::memcpy(&w,     tag + 20, 4);
    std::memcpy(&h,     tag + 24, 4);
    CHECK_EQ(addr,  0x1F000000ull);
    CHECK_EQ(pitch, 1280u * 4);
    CHECK_EQ(w,     1280u);
    CHECK_EQ(h,     1024u);
    CHECK_EQ((uint32_t)tag[28], 32u);  // bpp
    CHECK_EQ((uint32_t)tag[29],  1u);  // framebuffer_type = direct RGB
    CHECK_EQ((uint32_t)tag[31], 16u);  // red_field_position
    CHECK_EQ((uint32_t)tag[33],  8u);  // green_field_position
    CHECK_EQ((uint32_t)tag[35],  0u);  // blue_field_position
}

TEST(mb2_omits_framebuffer_tag_when_unset)
{
    Mb2Params p;
    p.ramBytes = 64ull * 1024 * 1024;
    auto blob  = BuildMultiboot2Info(p);
    uint32_t sz = 0;
    CHECK(FindTag(blob, 8, sz) == nullptr);
}

// Regression guard: when fbAddr==0 the mmap must be exactly two entries —
// one low-reserved and one big available — byte-identical to the pre-FB
// layout.
TEST(mb2_mmap_no_fb_is_two_entries)
{
    Mb2Params p;
    p.ramBytes    = 64ull * 1024 * 1024;
    p.reservedEnd = 0x200000;
    auto blob     = BuildMultiboot2Info(p);
    auto entries  = ParseMmap(blob);
    CHECK_EQ(entries.size(), size_t(2));
    // entry 0: [0, reservedEnd) reserved
    CHECK_EQ(entries[0].base, 0ull);
    CHECK_EQ(entries[0].len,  0x200000ull);
    CHECK_EQ(entries[0].type, 2u);
    // entry 1: [reservedEnd, ramTop) available
    CHECK_EQ(entries[1].base, 0x200000ull);
    CHECK_EQ(entries[1].len,  64ull * 1024 * 1024 - 0x200000ull);
    CHECK_EQ(entries[1].type, 1u);
}

// When fbAddr is set the mmap must have three entries: low-reserved,
// available up to fbAddr, then fb-reserved from fbAddr to RAM top.
TEST(mb2_mmap_fb_splits_available_entry)
{
    constexpr uint64_t kRam      = 64ull * 1024 * 1024;
    constexpr uint64_t kResEnd   = 0x200000;
    constexpr uint64_t kFbAddr   = 0x3C00000; // 60 MiB — well-aligned
    Mb2Params p;
    p.ramBytes    = kRam;
    p.reservedEnd = kResEnd;
    p.fbAddr      = kFbAddr;
    p.fbWidth     = 1280;
    p.fbHeight    = 1024;
    p.fbPitch     = 1280 * 4;
    p.fbBpp       = 32;
    auto blob    = BuildMultiboot2Info(p);
    auto entries = ParseMmap(blob);
    CHECK_EQ(entries.size(), size_t(3));
    // entry 0: low reserved
    CHECK_EQ(entries[0].base, 0ull);
    CHECK_EQ(entries[0].len,  kResEnd);
    CHECK_EQ(entries[0].type, 2u);
    // entry 1: available RAM below FB
    CHECK_EQ(entries[1].base, kResEnd);
    CHECK_EQ(entries[1].len,  kFbAddr - kResEnd);
    CHECK_EQ(entries[1].type, 1u);
    // entry 2: framebuffer reserved up to RAM top
    CHECK_EQ(entries[2].base, kFbAddr);
    CHECK_EQ(entries[2].len,  kRam - kFbAddr);
    CHECK_EQ(entries[2].type, 2u);
}
