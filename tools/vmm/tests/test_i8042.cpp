#include "test_main.h"
#include "devices/ps2_i8042.h"
#include <vector>

using duetos::vmm::Ps2I8042;

TEST(i8042_self_test_and_kbd_byte_flow)
{
    std::vector<uint32_t> irqs;
    Ps2I8042 c([&](uint32_t i){ irqs.push_back(i); });

    c.Out(0x64, 0xAA);
    CHECK((c.In(0x64) & 0x01) != 0);
    CHECK_EQ((int)c.In(0x60), 0x55);

    uint8_t k = 0x1C;
    c.PushKey(&k, 1);
    CHECK((c.In(0x64) & 0x01) != 0);
    CHECK((c.In(0x64) & 0x20) == 0);
    bool sawIrq1 = false;
    for (auto i : irqs) if (i == 1) sawIrq1 = true;
    CHECK(sawIrq1);
    CHECK_EQ((int)c.In(0x60), 0x1C);
    CHECK((c.In(0x64) & 0x01) == 0);
}

// The kernel ps2mouse driver issues 0xA9 (test second PS/2 port) and
// requires 0x00 (pass) or it concludes "no PS/2 mouse" and never
// processes AUX bytes — defeating window mouse input. Mirrors the
// existing 0xAB port-1 test contract.
TEST(i8042_port2_interface_test_passes)
{
    std::vector<uint32_t> irqs;
    Ps2I8042 c([&](uint32_t i){ irqs.push_back(i); });

    c.Out(0x64, 0xA9);
    CHECK((c.In(0x64) & 0x01) != 0);     // output buffer full
    CHECK_EQ((int)c.In(0x60), 0x00);     // 0x00 == port 2 OK
}

TEST(i8042_aux_routes_to_irq12_and_sets_bit5)
{
    std::vector<uint32_t> irqs;
    Ps2I8042 c([&](uint32_t i){ irqs.push_back(i); });
    c.Out(0x64, 0xA8);
    uint8_t m = 0x08;
    c.PushAux(&m, 1);
    CHECK((c.In(0x64) & 0x20) != 0);
    bool sawIrq12 = false;
    for (auto i : irqs) if (i == 12) sawIrq12 = true;
    CHECK(sawIrq12);
    CHECK_EQ((int)c.In(0x60), 0x08);
}
