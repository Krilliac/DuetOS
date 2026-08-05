// test_xhci_hid_composite.cpp — hosted test for the composite-HID
// claim in kernel/drivers/usb/xhci_descparse.cpp.
//
// Covers ParseConfigForHidBoot's multi-interface behaviour: a
// composite device whose non-boot HID interface is enumerated AHEAD
// of its boot keyboard must yield BOTH interfaces with their own
// endpoint, report-descriptor length and interval. Under the old
// first-match-wins claim the keyboard was shadowed and lost, which is
// exactly the shape real gaming keyboards and headsets ship.
//
// Also pins the single-interface boot-mouse path so the composite
// work cannot regress the keyboard/mouse bring-up that already
// worked, plus the parser's defensive edges: alternate settings are
// skipped, duplicate interface numbers are not double-claimed,
// interfaces without an interrupt-IN endpoint are dropped, and
// interfaces past kMaxHidInterfacesPerPort are counted rather than
// silently ignored. main() finally runs the driver's own
// XhciDescriptorSelfTest so its in-kernel fixtures (including the
// composite one) are checked here too, not only at boot.
//
// The parser is pure logic over a byte buffer, but its translation
// unit reaches for the kernel's serial console and panic path on the
// mismatch leg of its own self-test. Those two symbols are stubbed
// below so the real parser source can be compiled and linked here
// unchanged — no copy of the descriptor walk lives in this file.

#include "host_test_helper.h"

#include "drivers/usb/xhci.h"
#include "drivers/usb/xhci_internal.h"

using duetos::u32;
using duetos::u8;
using duetos::drivers::usb::xhci::HidIfaceKind;
using duetos::drivers::usb::xhci::kMaxHidInterfacesPerPort;
using duetos::drivers::usb::xhci::PortRecord;
using duetos::drivers::usb::xhci::internal::ParseConfigForHidBoot;

// Host stubs for the two kernel symbols xhci_descparse.cpp reaches
// for. Both live only on the mismatch leg of the driver's own
// XhciDescriptorSelfTest, which this test also runs — a mismatch
// there must fail the hosted run, and PanicWithValue is [[noreturn]]
// in the kernel, so the stub exits non-zero rather than returning.
namespace duetos::arch
{

void SerialWrite(const char* s)
{
    if (s != nullptr)
        std::fputs(s, stdout);
}

void SerialWriteHex(duetos::u64 v)
{
    std::printf("0x%llx", static_cast<unsigned long long>(v));
}

} // namespace duetos::arch

namespace duetos::core
{

[[noreturn]] void PanicWithValue(const char* subsystem, const char* message, duetos::u64 value)
{
    std::printf("FAIL: kernel panic from %s: %s (value=0x%llx)\n", subsystem != nullptr ? subsystem : "?",
                message != nullptr ? message : "?", static_cast<unsigned long long>(value));
    std::exit(1);
}

} // namespace duetos::core

namespace
{

// USB descriptor tags, spelled locally so the fixtures below read as
// the wire bytes they are.
constexpr u8 kConfig = 0x02;
constexpr u8 kInterface = 0x04;
constexpr u8 kEndpoint = 0x05;
constexpr u8 kHid = 0x21;
constexpr u8 kReport = 0x22;
constexpr u8 kClassHid = 0x03;
constexpr u8 kSubclassBoot = 0x01;
constexpr u8 kProtoKeyboard = 0x01;
constexpr u8 kProtoMouse = 0x02;
constexpr u8 kInterruptEp = 0x03;

// Composite: non-boot HID interface 4 (EP 0x83) FIRST, boot keyboard
// interface 5 (EP 0x81) second. wTotalLength = 9 + 25 + 25 = 0x3B.
// clang-format off
constexpr u8 kGamepadThenKeyboard[] = {
    // Configuration: 2 interfaces, wTotalLength 0x3B.
    0x09, kConfig, 0x3B, 0x00, 0x02, 0x01, 0x00, 0xA0, 0x32,
    // interface 4 — non-boot HID (gamepad candidate), EP 0x83 IN
    0x09, kInterface, 0x04, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x90, 0x00,
    0x07, kEndpoint, 0x83, kInterruptEp, 0x20, 0x00, 0x08,
    // interface 5 — boot keyboard, EP 0x81 IN
    0x09, kInterface, 0x05, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x81, kInterruptEp, 0x08, 0x00, 0x0A,
};
// clang-format on

// Single boot mouse, interface 3, EP 0x81. wTotalLength = 0x22.
// clang-format off
constexpr u8 kPlainMouse[] = {
    0x09, kConfig, 0x22, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32,
    0x09, kInterface, 0x03, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoMouse, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x7B, 0x00,
    0x07, kEndpoint, 0x81, kInterruptEp, 0x10, 0x00, 0x08,
};
// clang-format on

// Boot keyboard whose only endpoint is interrupt-OUT (an LED-report
// endpoint). No interrupt-IN means nothing to poll, so the interface
// must be dropped and the aggregate flag must stay clear.
// clang-format off
constexpr u8 kKeyboardNoInEndpoint[] = {
    0x09, kConfig, 0x22, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32,
    0x09, kInterface, 0x01, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x02, kInterruptEp, 0x08, 0x00, 0x0A, // 0x02 = OUT direction
};
// clang-format on

// Boot keyboard at alt setting 0 (EP 0x81) followed by the SAME
// interface number at alt setting 1 (EP 0x82). We never issue
// SET_INTERFACE, so the alt setting must be skipped entirely and the
// alt-0 endpoint must survive. wTotalLength = 9 + 25 + 25 = 0x3B.
// clang-format off
constexpr u8 kKeyboardWithAltSetting[] = {
    0x09, kConfig, 0x3B, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32,
    // alt 0 — the reachable setting, EP 0x81 IN
    0x09, kInterface, 0x01, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x81, kInterruptEp, 0x08, 0x00, 0x0A,
    // alt 1 — same interface number, must be skipped entirely
    0x09, kInterface, 0x01, 0x01, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x82, kInterruptEp, 0x40, 0x00, 0x01,
};
// clang-format on

// Malformed tree: the SAME interface number twice, both at alt
// setting 0, with different endpoints. Claiming it twice would
// program one endpoint onto two records and double-count the
// aggregate, so the repeat must be ignored outright.
// wTotalLength = 9 + 25 + 25 = 0x3B.
// clang-format off
constexpr u8 kDuplicateInterfaceNumber[] = {
    0x09, kConfig, 0x3B, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32,
    0x09, kInterface, 0x02, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x81, kInterruptEp, 0x08, 0x00, 0x0A,
    // repeat of interface 2 at alt 0 — must not be claimed again
    0x09, kInterface, 0x02, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x55, 0x00,
    0x07, kEndpoint, 0x84, kInterruptEp, 0x20, 0x00, 0x04,
};
// clang-format on

// Five HID interfaces (numbers 0..4), each with its own interrupt-IN
// endpoint. One more than kMaxHidInterfacesPerPort, so the last must
// land in hid_ifaces_dropped rather than overrun the array.
// wTotalLength = 9 + 5 * 25 = 134 = 0x86.
// clang-format off
constexpr u8 kFiveHidInterfaces[] = {
    0x09, kConfig, 0x86, 0x00, 0x05, 0x01, 0x00, 0xA0, 0x32,
    0x09, kInterface, 0x00, 0x00, 0x01, kClassHid, kSubclassBoot, kProtoKeyboard, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x41, 0x00,
    0x07, kEndpoint, 0x81, kInterruptEp, 0x08, 0x00, 0x0A,
    0x09, kInterface, 0x01, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x42, 0x00,
    0x07, kEndpoint, 0x82, kInterruptEp, 0x08, 0x00, 0x0A,
    0x09, kInterface, 0x02, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x43, 0x00,
    0x07, kEndpoint, 0x83, kInterruptEp, 0x08, 0x00, 0x0A,
    0x09, kInterface, 0x03, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x44, 0x00,
    0x07, kEndpoint, 0x84, kInterruptEp, 0x08, 0x00, 0x0A,
    // fifth interface — one past kMaxHidInterfacesPerPort
    0x09, kInterface, 0x04, 0x00, 0x01, kClassHid, 0x00, 0x00, 0x00,
    0x09, kHid, 0x11, 0x01, 0x00, 0x01, kReport, 0x45, 0x00,
    0x07, kEndpoint, 0x85, kInterruptEp, 0x08, 0x00, 0x0A,
};
// clang-format on

} // namespace

void composite_gamepad_then_keyboard_claims_both()
{
    PortRecord port{};
    EXPECT_TRUE(ParseConfigForHidBoot(kGamepadThenKeyboard, sizeof(kGamepadThenKeyboard), port));

    EXPECT_EQ(u32(port.hid_iface_count), 2u);
    EXPECT_EQ(u32(port.hid_ifaces_dropped), 0u);
    EXPECT_EQ(u32(port.hid_config_value), 1u);

    // The regression this test exists for: the boot keyboard sat
    // BEHIND a non-boot HID interface and used to be shadowed away.
    EXPECT_TRUE(port.hid_keyboard);
    EXPECT_TRUE(port.hid_gamepad);
    EXPECT_TRUE(!port.hid_mouse);

    EXPECT_EQ(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::GamepadCandidate));
    EXPECT_EQ(u32(port.hid_ifaces[0].interface_num), 4u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_addr), 0x83u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_max_packet), 0x20u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_interval), 0x08u);
    EXPECT_EQ(u32(port.hid_ifaces[0].report_desc_length), 0x90u);

    EXPECT_EQ(u32(port.hid_ifaces[1].kind), u32(HidIfaceKind::BootKeyboard));
    EXPECT_EQ(u32(port.hid_ifaces[1].interface_num), 5u);
    EXPECT_EQ(u32(port.hid_ifaces[1].ep_addr), 0x81u);
    EXPECT_EQ(u32(port.hid_ifaces[1].ep_max_packet), 0x08u);
    EXPECT_EQ(u32(port.hid_ifaces[1].ep_interval), 0x0Au);
    EXPECT_EQ(u32(port.hid_ifaces[1].report_desc_length), 0x41u);

    // Endpoints must not be cross-attached: each interface owns its
    // own, which is what lets the poll task route by endpoint.
    EXPECT_TRUE(port.hid_ifaces[0].ep_addr != port.hid_ifaces[1].ep_addr);
}

void single_boot_mouse_unchanged()
{
    PortRecord port{};
    EXPECT_TRUE(ParseConfigForHidBoot(kPlainMouse, sizeof(kPlainMouse), port));
    EXPECT_EQ(u32(port.hid_iface_count), 1u);
    EXPECT_TRUE(port.hid_mouse);
    EXPECT_TRUE(!port.hid_keyboard);
    EXPECT_TRUE(!port.hid_gamepad);
    EXPECT_EQ(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::BootMouse));
    EXPECT_EQ(u32(port.hid_ifaces[0].interface_num), 3u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_addr), 0x81u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_max_packet), 0x10u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_interval), 0x08u);
    EXPECT_EQ(u32(port.hid_ifaces[0].report_desc_length), 0x7Bu);
}

void interface_without_interrupt_in_is_dropped()
{
    PortRecord port{};
    // No pollable endpoint anywhere, so the parse reports failure and
    // the aggregate must NOT advertise a keyboard the bring-up path
    // would then try to configure against DCI 0.
    EXPECT_TRUE(!ParseConfigForHidBoot(kKeyboardNoInEndpoint, sizeof(kKeyboardNoInEndpoint), port));
    EXPECT_EQ(u32(port.hid_iface_count), 0u);
    EXPECT_TRUE(!port.hid_keyboard);
}

void alternate_setting_does_not_shadow_alt_zero()
{
    PortRecord port{};
    EXPECT_TRUE(ParseConfigForHidBoot(kKeyboardWithAltSetting, sizeof(kKeyboardWithAltSetting), port));
    EXPECT_EQ(u32(port.hid_iface_count), 1u);
    EXPECT_TRUE(port.hid_keyboard);
    // The alt-1 endpoint (0x82, mps 0x40) must not have replaced or
    // supplemented the alt-0 one.
    EXPECT_EQ(u32(port.hid_ifaces[0].interface_num), 1u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_addr), 0x81u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_max_packet), 0x08u);
}

void duplicate_interface_number_is_claimed_once()
{
    PortRecord port{};
    EXPECT_TRUE(ParseConfigForHidBoot(kDuplicateInterfaceNumber, sizeof(kDuplicateInterfaceNumber), port));
    EXPECT_EQ(u32(port.hid_iface_count), 1u);
    // The first claim stands; the repeat's kind, endpoint and report
    // length must not have leaked into it.
    EXPECT_EQ(u32(port.hid_ifaces[0].kind), u32(HidIfaceKind::BootKeyboard));
    EXPECT_EQ(u32(port.hid_ifaces[0].interface_num), 2u);
    EXPECT_EQ(u32(port.hid_ifaces[0].ep_addr), 0x81u);
    EXPECT_EQ(u32(port.hid_ifaces[0].report_desc_length), 0x41u);
    EXPECT_TRUE(port.hid_keyboard);
    EXPECT_TRUE(!port.hid_gamepad);
}

void interfaces_past_cap_are_counted_not_overrun()
{
    PortRecord port{};
    EXPECT_TRUE(ParseConfigForHidBoot(kFiveHidInterfaces, sizeof(kFiveHidInterfaces), port));
    EXPECT_EQ(u32(port.hid_iface_count), u32(kMaxHidInterfacesPerPort));
    EXPECT_EQ(u32(port.hid_ifaces_dropped), 1u);
    // The four that fit are the first four in descriptor order.
    for (u8 i = 0; i < u8(kMaxHidInterfacesPerPort); ++i)
    {
        EXPECT_EQ(u32(port.hid_ifaces[i].interface_num), u32(i));
        EXPECT_EQ(u32(port.hid_ifaces[i].ep_addr), u32(0x81u + i));
    }
}

void parse_rejects_truncated_and_null_input()
{
    PortRecord port{};
    EXPECT_TRUE(!ParseConfigForHidBoot(nullptr, 64, port));
    EXPECT_TRUE(!ParseConfigForHidBoot(kPlainMouse, 4, port));
    // A Configuration descriptor claiming a bLength below the 9-byte
    // header must not be walked.
    u8 stunted[16] = {};
    stunted[0] = 0x04;
    stunted[1] = kConfig;
    EXPECT_TRUE(!ParseConfigForHidBoot(stunted, sizeof(stunted), port));
}

int main()
{
    composite_gamepad_then_keyboard_claims_both();
    single_boot_mouse_unchanged();
    interface_without_interrupt_in_is_dropped();
    alternate_setting_does_not_shadow_alt_zero();
    duplicate_interface_number_is_claimed_once();
    interfaces_past_cap_are_counted_not_overrun();
    parse_rejects_truncated_and_null_input();
    // Run the driver's own boot self-test against its in-kernel
    // fixtures too. Its mismatch leg calls PanicWithValue, which the
    // stub above turns into a non-zero exit, so a bad in-kernel
    // fixture fails this hosted run instead of waiting for a boot.
    duetos::drivers::usb::xhci::internal::XhciDescriptorSelfTest();
    return duetos_host_test::finish_main("xhci_hid_composite");
}
