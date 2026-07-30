/*
 * test_font_registry.cpp — hosted unit test for the font registry
 * (kernel/subsystems/graphics/font.h + font.cpp).
 *
 * Exercises:
 *   - FontRegistryInit registers 3 built-in fonts (System, Fixedsys,
 *     Terminal).
 *   - FontRegistryLookup matches by name (case-insensitive), falls
 *     back to height-based selection, and always returns System as
 *     the final fallback.
 *   - FontRegistryGet returns valid entries for in-range indices and
 *     nullptr for out-of-range.
 *   - FontRegistryCount reflects the correct number of alive entries.
 *   - FontEntry::LookupGlyph dispatches correctly for 8x8 and 8x16
 *     fonts and returns non-null for printable ASCII.
 */

#include "host_test_helper.h"
#include "subsystems/graphics/font.h"

using namespace duetos::subsystems::graphics;
using duetos::u32;
using duetos::u8;

int main()
{
    // Init the registry — safe to call multiple times.
    FontRegistryInit();
    FontRegistryInit(); // idempotent

    // --- Count and slots ---
    EXPECT_EQ(FontRegistryCount(), 3u);

    const FontEntry* slot0 = FontRegistryGet(0);
    const FontEntry* slot1 = FontRegistryGet(1);
    const FontEntry* slot2 = FontRegistryGet(2);
    ASSERT_TRUE(slot0 != nullptr);
    ASSERT_TRUE(slot1 != nullptr);
    ASSERT_TRUE(slot2 != nullptr);

    // Out-of-range returns nullptr.
    EXPECT_TRUE(FontRegistryGet(3) == nullptr);
    EXPECT_TRUE(FontRegistryGet(100) == nullptr);

    // --- Slot 0: System 8x8 ---
    EXPECT_STREQ(slot0->name, "System");
    EXPECT_EQ(slot0->glyph_width, 8u);
    EXPECT_EQ(slot0->glyph_height, 8u);
    EXPECT_EQ(slot0->weight, kFwNormal);
    EXPECT_FALSE(slot0->italic);

    // --- Slot 1: Fixedsys 8x8 ---
    EXPECT_STREQ(slot1->name, "Fixedsys");
    EXPECT_EQ(slot1->glyph_width, 8u);
    EXPECT_EQ(slot1->glyph_height, 8u);

    // --- Slot 2: Terminal 8x16 ---
    EXPECT_STREQ(slot2->name, "Terminal");
    EXPECT_EQ(slot2->glyph_width, 8u);
    EXPECT_EQ(slot2->glyph_height, 16u);

    // --- Lookup by exact name ---
    const FontEntry* sys = FontRegistryLookup("System", 8, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(sys != nullptr);
    EXPECT_EQ(sys->glyph_height, 8u);
    EXPECT_STREQ(sys->name, "System");

    const FontEntry* term = FontRegistryLookup("Terminal", 16, kFwNormal, false, kOemCharset);
    ASSERT_TRUE(term != nullptr);
    EXPECT_EQ(term->glyph_height, 16u);
    EXPECT_STREQ(term->name, "Terminal");

    // Case-insensitive name match.
    const FontEntry* sys2 = FontRegistryLookup("SYSTEM", 8, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(sys2 != nullptr);
    EXPECT_STREQ(sys2->name, "System");

    const FontEntry* fixed = FontRegistryLookup("fixedsys", 8, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(fixed != nullptr);
    EXPECT_STREQ(fixed->name, "Fixedsys");

    // --- Lookup with height preference ---
    // Height >= 12 with no name match should prefer Terminal (8x16).
    const FontEntry* tall = FontRegistryLookup("Arial", 14, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(tall != nullptr);
    EXPECT_EQ(tall->glyph_height, 16u);

    // Height < 12 with no name match should fall back to System (8x8).
    const FontEntry* small = FontRegistryLookup("Arial", 8, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(small != nullptr);
    EXPECT_EQ(small->glyph_height, 8u);

    // --- LookupGlyph ---
    // 8x8 font glyphs: printable ASCII should return non-null.
    const u8* glyph_a = slot0->LookupGlyph('A');
    ASSERT_TRUE(glyph_a != nullptr);
    // 'A' is not blank — at least one row should be non-zero.
    bool has_pixels = false;
    for (int i = 0; i < 8; ++i)
    {
        if (glyph_a[i] != 0)
            has_pixels = true;
    }
    EXPECT_TRUE(has_pixels);

    // 8x16 font glyphs: printable ASCII should return non-null.
    const u8* glyph_b = slot2->LookupGlyph('B');
    ASSERT_TRUE(glyph_b != nullptr);
    has_pixels = false;
    for (int i = 0; i < 16; ++i)
    {
        if (glyph_b[i] != 0)
            has_pixels = true;
    }
    EXPECT_TRUE(has_pixels);

    // Space glyph should be all zeros for 8x8.
    const u8* glyph_space = slot0->LookupGlyph(' ');
    ASSERT_TRUE(glyph_space != nullptr);
    bool all_zero = true;
    for (int i = 0; i < 8; ++i)
    {
        if (glyph_space[i] != 0)
            all_zero = false;
    }
    EXPECT_TRUE(all_zero);

    // --- FontRegistryAdd (manually add a 4th font) ---
    u32 idx = FontRegistryAdd("Courier", nullptr, 8, 8, kFwNormal, false, kAnsiCharset);
    EXPECT_EQ(idx, 3u);
    EXPECT_EQ(FontRegistryCount(), 4u);
    const FontEntry* courier = FontRegistryGet(3);
    ASSERT_TRUE(courier != nullptr);
    EXPECT_STREQ(courier->name, "Courier");

    // Lookup by name should find the new font.
    const FontEntry* found = FontRegistryLookup("Courier", 8, kFwNormal, false, kDefaultCharset);
    ASSERT_TRUE(found != nullptr);
    EXPECT_STREQ(found->name, "Courier");

    return duetos_host_test::finish_main("font_registry");
}
