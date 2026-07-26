// Synthetic malformed/boundary tests for the PE32+ unwind image view.
//
// This exercises the same C-compatible header used by both ntdll and
// kernel32 before either mirror forms a .pdata/.xdata/handler pointer.

#include "host_test_helper.h"
#include "../../userland/libs/common/pe_unwind_bounds.h"

namespace
{

void put16(unsigned char* p, unsigned int value)
{
    p[0] = static_cast<unsigned char>(value);
    p[1] = static_cast<unsigned char>(value >> 8);
}

void put32(unsigned char* p, unsigned int value)
{
    p[0] = static_cast<unsigned char>(value);
    p[1] = static_cast<unsigned char>(value >> 8);
    p[2] = static_cast<unsigned char>(value >> 16);
    p[3] = static_cast<unsigned char>(value >> 24);
}

struct Fixture
{
    unsigned char image[0x3000]{};

    Fixture()
    {
        image[0] = 'M';
        image[1] = 'Z';
        put32(image + 0x3C, 0x80);

        unsigned char* nt = image + 0x80;
        nt[0] = 'P';
        nt[1] = 'E';
        put16(nt + 6, 2);
        put16(nt + 20, 0xF0);

        unsigned char* optional = nt + 24;
        put16(optional, 0x20B);
        put32(optional + 0x38, 0x3000);
        put32(optional + 0x3C, 0x200);
        put32(optional + 0x6C, 4);
        put32(optional + 0x88, 0x2000);
        put32(optional + 0x8C, 12);

        unsigned char* text = optional + 0xF0;
        put32(text + 8, 0x400);
        put32(text + 12, 0x1000);
        put32(text + 36, DUET_PE_SCN_MEM_EXECUTE);

        unsigned char* metadata = text + 40;
        put32(metadata + 8, 0x500);
        put32(metadata + 12, 0x2000);

        put32(image + 0x2000, 0x1000);
        put32(image + 0x2004, 0x1100);
        put32(image + 0x2008, 0x2100);

        image[0x2100] = 9; // version 1 | UNW_FLAG_EHANDLER
        image[0x2101] = 5;
        image[0x2102] = 0;
        image[0x2103] = 0;
        put32(image + 0x2104, 0x1050);
        put32(image + 0x2108, 0);
    }
};

void make_chained(Fixture& f)
{
    put32(f.image + 0x80 + 24 + 0x8C, 24);

    // Primary: establishes RBP at prologue offset 5.
    f.image[0x2100] = 1;
    f.image[0x2101] = 5;
    f.image[0x2102] = 1;
    f.image[0x2103] = 0x25;          // frame register RBP, scaled offset 2
    put16(f.image + 0x2104, 0x0305); // SET_FPREG, CodeOffset 5

    // Secondary: no SET_FPREG; saves RBX at CodeOffset 8 and chains
    // to the already-executed primary prologue.
    put32(f.image + 0x200C, 0x1200);
    put32(f.image + 0x2010, 0x1300);
    put32(f.image + 0x2014, 0x2200);
    f.image[0x2200] = 0x21; // version 1 | CHAININFO
    f.image[0x2201] = 10;
    f.image[0x2202] = 2;
    f.image[0x2203] = 0x25;
    put16(f.image + 0x2204, 0x3408); // SAVE_NONVOL RBX, CodeOffset 8
    put16(f.image + 0x2206, 2);      // frame-base + 16
    put32(f.image + 0x2208, 0x1000);
    put32(f.image + 0x220C, 0x1100);
    put32(f.image + 0x2210, 0x2100);
}

} // namespace

int main()
{
    {
        Fixture f;
        DUET_PE_VIEW view{};
        EXPECT_TRUE(duet_pe_parse(f.image, &view));
        EXPECT_EQ(view.size, 0x3000u);
        const void* function = f.image + 0x2000;
        EXPECT_TRUE(duet_pe_runtime_function_pointer(&view, function));
        DUET_PE_UNWIND_LAYOUT layout{};
        EXPECT_TRUE(duet_pe_unwind_layout(&view, function, &layout));
        EXPECT_EQ(layout.flags, 1u);
        EXPECT_TRUE(duet_pe_rva_executable(&view, 0x1050));
        EXPECT_FALSE(duet_pe_rva_executable(&view, 0x3000)); // exact image end is out-of-bounds
        EXPECT_FALSE(duet_pe_rva_executable(&view, 0x2050)); // zero characteristics fail closed
        put32(f.image + 0x188 + 40 + 36, 0x40000000);
        EXPECT_FALSE(duet_pe_rva_executable(&view, 0x2050)); // readable but non-executable fails closed
        EXPECT_FALSE(duet_pe_runtime_function_pointer(&view, f.image + 0x2001));
    }
    {
        Fixture f;
        put32(f.image + 0x3C, 0xFF0);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // NT headers leave first mapped page
    }
    {
        Fixture f;
        put16(f.image + 0x80 + 6, 100);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // section table leaves first mapped page
    }
    {
        Fixture f;
        put32(f.image + 0x80 + 24 + 0x8C, 13);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // partial RUNTIME_FUNCTION
    }
    {
        Fixture f;
        put32(f.image + 0x80 + 24 + 0x88, 0x1800);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // pdata points into an unmapped image gap
    }
    {
        Fixture f;
        put32(f.image + 0x2004, 0x3001);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // function end past SizeOfImage
    }
    {
        Fixture f;
        put32(f.image + 0x80 + 24 + 0x8C, 24);
        put32(f.image + 0x200C, 0x1080);
        put32(f.image + 0x2010, 0x1200);
        put32(f.image + 0x2014, 0x2100);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // overlapping runtime-function ranges
    }
    {
        Fixture f;
        put32(f.image + 0x188 + 40 + 8, 0x20);
        put32(f.image + 0x188 + 40 + 12, 0x2FF0);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // section range crosses SizeOfImage
    }
    {
        Fixture f;
        put32(f.image + 0x2008, 0x2FFE);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // UNWIND_INFO header straddles image end
    }
    {
        Fixture f;
        put32(f.image + 0x2008, 0x1800);
        DUET_PE_VIEW view{};
        EXPECT_FALSE(duet_pe_parse(f.image, &view)); // UNWIND_INFO points into an unmapped image gap
    }
    {
        Fixture f;
        DUET_PE_VIEW view{};
        EXPECT_TRUE(duet_pe_parse(f.image, &view));
        f.image[0x2100] = 0x29; // version 1 | CHAININFO | EHANDLER is forbidden
        DUET_PE_UNWIND_LAYOUT layout{};
        EXPECT_FALSE(duet_pe_unwind_layout(&view, f.image + 0x2000, &layout));
    }
    {
        Fixture f;
        DUET_PE_VIEW view{};
        EXPECT_TRUE(duet_pe_parse(f.image, &view));
        put32(f.image + 0x2008, 0x2FF8);
        f.image[0x2FF8] = 9;
        f.image[0x2FFA] = 0;
        DUET_PE_UNWIND_LAYOUT layout{};
        EXPECT_FALSE(duet_pe_unwind_layout(&view, f.image + 0x2000, &layout)); // handler tail exceeds image
    }
    {
        Fixture f;
        put32(f.image + 0x2008, 0x24FC);
        f.image[0x24FC] = 9;
        DUET_PE_VIEW view{};
        EXPECT_TRUE(duet_pe_parse(f.image, &view));
        DUET_PE_UNWIND_LAYOUT layout{};
        EXPECT_FALSE(duet_pe_unwind_layout(&view, f.image + 0x2000, &layout)); // tail crosses into mapped gap
    }
    {
        Fixture f;
        make_chained(f);
        DUET_PE_VIEW view{};
        EXPECT_TRUE(duet_pe_parse(f.image, &view));
        const void* secondary = f.image + 0x200C;
        EXPECT_TRUE(duet_pe_validate_unwind_chain(&view, secondary));

        DUET_PE_UNWIND_LAYOUT secondary_layout{};
        EXPECT_TRUE(duet_pe_unwind_layout(&view, secondary, &secondary_layout));
        EXPECT_EQ(((secondary_layout.codes[0] >> 8) & 0x0F), 4); // secondary SAVE_NONVOL
        unsigned int width = 0;
        EXPECT_TRUE(duet_pe_unwind_op_width(secondary_layout.codes[0], secondary_layout.frreg, &width));
        EXPECT_EQ(width, 2u);

        const auto base = reinterpret_cast<unsigned long long>(f.image);
        const unsigned int partial = duet_pe_prolog_offset(&secondary_layout, secondary, base, base + 0x1206);
        EXPECT_EQ(partial, 6u);
        EXPECT_TRUE((secondary_layout.codes[0] & 0xFFu) > partial); // SAVE not executed yet
        EXPECT_TRUE(duet_pe_chain_frame_established(&view, secondary, base, base + 0x1206));

        const unsigned int after_save = duet_pe_prolog_offset(&secondary_layout, secondary, base, base + 0x1209);
        EXPECT_TRUE((secondary_layout.codes[0] & 0xFFu) <= after_save);

        f.image[0x2103] = 0x15; // primary froff differs from secondary
        EXPECT_FALSE(duet_pe_validate_unwind_chain(&view, secondary));
    }

    return duetos_host_test::finish_main("pe_unwind_bounds");
}
