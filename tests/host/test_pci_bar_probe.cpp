// Hosted unit test for PCI BAR probe-mask decoding. Hardware config-space
// transaction ordering is covered by tools/test/test-pci-bar-sizing-contract.py;
// this test attacks the pure arithmetic and validation boundary with synthetic
// device responses that are impractical to obtain from one physical machine.

#include "host_test_helper.h"

#include "drivers/pci/pci.h"

namespace pci = duetos::drivers::pci;

int main()
{
    // 32-bit prefetchable MMIO BAR: 4 KiB at 0x80000000.
    {
        const pci::Bar bar = pci::detail::DecodeBarProbe(0, 0x80000008u, 0, 0xFFFFF008u, 0);
        EXPECT_EQ(bar.address, 0x80000000ULL);
        EXPECT_EQ(bar.size, 0x1000ULL);
        EXPECT_FALSE(bar.is_io);
        EXPECT_FALSE(bar.is_64bit);
        EXPECT_TRUE(bar.is_prefetchable);
    }

    // I/O BAR: 256 ports at 0xC000. Type bits must not leak into either
    // the decoded address or the size mask.
    {
        const pci::Bar bar = pci::detail::DecodeBarProbe(2, 0x0000C001u, 0, 0xFFFFFF01u, 0);
        EXPECT_EQ(bar.address, 0xC000ULL);
        EXPECT_EQ(bar.size, 0x100ULL);
        EXPECT_TRUE(bar.is_io);
        EXPECT_FALSE(bar.is_64bit);
        EXPECT_FALSE(bar.is_prefetchable);
    }

    // A 64-bit, prefetchable BAR is decoded from one atomic low/high probe
    // snapshot. This one is 64 KiB at 0x12_0000_0000.
    {
        const pci::Bar bar = pci::detail::DecodeBarProbe(3, 0x0000000Cu, 0x00000012u, 0xFFFF000Cu, 0xFFFFFFFFu);
        EXPECT_EQ(bar.address, 0x0000001200000000ULL);
        EXPECT_EQ(bar.size, 0x10000ULL);
        EXPECT_FALSE(bar.is_io);
        EXPECT_TRUE(bar.is_64bit);
        EXPECT_TRUE(bar.is_prefetchable);
    }

    // Obsolete type 01 is still a valid memory BAR with a 20-bit address
    // field. Keep it for old commodity PCI cards without allowing upper-bit
    // residue to alias the decoded range.
    {
        const pci::Bar bar = pci::detail::DecodeBarProbe(1, 0x00080002u, 0, 0x000FF002u, 0);
        EXPECT_EQ(bar.address, 0x80000ULL);
        EXPECT_EQ(bar.size, 0x1000ULL);
        EXPECT_FALSE(bar.is_io);
        EXPECT_FALSE(bar.is_64bit);
        EXPECT_FALSE(bar.is_prefetchable);
    }

    // Empty, absent, and unimplemented-mask responses all fail closed.
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0, 0, 0, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0xFFFFFFFFu, 0, 0xFFFFFFFFu, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80000000u, 0, 0, 0).size, 0ULL);

    // Memory BAR encoding 11 is reserved, and a low half in slot 5 cannot
    // legally claim a missing high slot.
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80000006u, 0, 0xFFFFF006u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(5, 0x00000004u, 0, 0xFFFFF004u, 0xFFFFFFFFu).size, 0ULL);

    // Hostile masks, bases, or mutable attribute bits must not be rounded
    // into plausible resources.
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80000000u, 0, 0xFFFFEF00u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80000800u, 0, 0xFFFFF000u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80000008u, 0, 0xFFFFF000u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x0000C003u, 0, 0xFFFFFF03u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x80080002u, 0, 0x000FF002u, 0).size, 0ULL);
    EXPECT_EQ(pci::detail::DecodeBarProbe(0, 0x00080002u, 0, 0x800FF002u, 0).size, 0ULL);

    // Exercise every representable power-of-two size for each supported
    // format. The base is one aligned region above zero and the largest case
    // ends exactly at its width limit, covering boundary arithmetic without
    // invoking signed or wrapping shifts.
    for (duetos::u32 power = 4; power < 32; ++power)
    {
        const duetos::u64 size = 1ULL << power;
        const duetos::u32 base = static_cast<duetos::u32>(size);
        const duetos::u32 probe = static_cast<duetos::u32>((~(size - 1)) & 0xFFFFFFF0ULL);
        const pci::Bar bar = pci::detail::DecodeBarProbe(0, base, 0, probe, 0);
        EXPECT_EQ(bar.address, size);
        EXPECT_EQ(bar.size, size);
    }

    for (duetos::u32 power = 2; power < 32; ++power)
    {
        const duetos::u64 size = 1ULL << power;
        const duetos::u32 base = static_cast<duetos::u32>(size);
        const duetos::u32 probe = static_cast<duetos::u32>((~(size - 1)) & 0xFFFFFFFCULL);
        const pci::Bar bar = pci::detail::DecodeBarProbe(0, base | 0x1u, 0, probe | 0x1u, 0);
        EXPECT_EQ(bar.address, size);
        EXPECT_EQ(bar.size, size);
        EXPECT_TRUE(bar.is_io);
    }

    for (duetos::u32 power = 4; power < 20; ++power)
    {
        const duetos::u64 size = 1ULL << power;
        const duetos::u32 base = static_cast<duetos::u32>(size);
        const duetos::u32 probe = static_cast<duetos::u32>((~(size - 1)) & 0x000FFFF0ULL);
        const pci::Bar bar = pci::detail::DecodeBarProbe(0, base | 0x2u, 0, probe | 0x2u, 0);
        EXPECT_EQ(bar.address, size);
        EXPECT_EQ(bar.size, size);
    }

    for (duetos::u32 power = 4; power < 64; ++power)
    {
        const duetos::u64 size = 1ULL << power;
        const duetos::u64 base = size;
        const duetos::u64 probe = ~(size - 1);
        const pci::Bar bar =
            pci::detail::DecodeBarProbe(0, static_cast<duetos::u32>(base) | 0x4u, static_cast<duetos::u32>(base >> 32),
                                        static_cast<duetos::u32>(probe) | 0x4u, static_cast<duetos::u32>(probe >> 32));
        EXPECT_EQ(bar.address, size);
        EXPECT_EQ(bar.size, size);
        EXPECT_TRUE(bar.is_64bit);
    }

    return ::duetos_host_test::finish_main("test_pci_bar_probe");
}
