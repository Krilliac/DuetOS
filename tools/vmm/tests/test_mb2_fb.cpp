#include "test_main.h"
#include "multiboot2.h"
#include <cstring>

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
