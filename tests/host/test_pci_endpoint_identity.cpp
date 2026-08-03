// Hosted test for the pure PCI standard-header identity decoder. It covers
// byte layout, multifunction type-0 endpoints, hostile subsystem values, and
// the requirement that bridge/CardBus register 0x2C is never treated as a
// subsystem tuple.

#include "host_test_helper.h"

#include "drivers/pci/pci.h"

namespace pci = duetos::drivers::pci;

int main()
{
    constexpr pci::DeviceAddress address{.bus = 3, .device = 17, .function = 5, ._pad = 0xA5};

    // MT7921-shaped multifunction endpoint. Standard config dwords are
    // little-endian: revision is byte 0, programming interface byte 1,
    // subclass byte 2, and class byte 3.
    {
        constexpr pci::Device device =
            pci::detail::DecodeDeviceIdentity(address, 0x792214C3u, 0x02000101u, 0x00800000u, 0xE0B614C3u, true);
        static_assert(device.addr.bus == 3 && device.addr.device == 17 && device.addr.function == 5);
        static_assert(device.addr._pad == 0);
        static_assert(device.vendor_id == 0x14C3 && device.device_id == 0x7922);
        static_assert(device.class_code == 0x02 && device.subclass == 0x00);
        static_assert(device.programming_interface == 0x01 && device.revision_id == 0x01);
        static_assert(device.prog_if == device.programming_interface);
        static_assert(device.revision == device.revision_id);
        static_assert(device.header_type == 0x80); // preserve multifunction bit
        static_assert(device.subsystem_known);
        static_assert(device.subsystem_vendor_id == 0x14C3 && device.subsystem_device_id == 0xE0B6);
    }

    // A plausible dword at 0x2C must be ignored for both bridge layouts,
    // including a multifunction bridge, and for CardBus.
    constexpr duetos::u8 non_endpoint_headers[] = {0x01, 0x81, 0x02};
    for (const duetos::u8 header_type : non_endpoint_headers)
    {
        const pci::Device device = pci::detail::DecodeDeviceIdentity(address, 0x12348086u, 0x060400ABu,
                                                                     duetos::u32(header_type) << 16, 0xE0B614C3u, true);
        EXPECT_EQ(device.header_type, header_type);
        EXPECT_EQ(device.class_code, 0x06);
        EXPECT_EQ(device.subclass, 0x04);
        EXPECT_EQ(device.programming_interface, 0x00);
        EXPECT_EQ(device.revision_id, 0xAB);
        EXPECT_FALSE(device.subsystem_known);
        EXPECT_EQ(device.subsystem_vendor_id, 0);
        EXPECT_EQ(device.subsystem_device_id, 0);
    }

    // Exhaust the header-type byte. Only type zero, with or without the
    // multifunction bit, may interpret 0x2C as subsystem identity.
    for (duetos::u32 raw_header = 0; raw_header <= 0xFFu; ++raw_header)
    {
        const pci::Device device =
            pci::detail::DecodeDeviceIdentity(address, 0x792214C3u, 0x02000101u, raw_header << 16, 0xE0B614C3u, true);
        const bool endpoint_layout = (raw_header & 0x7Fu) == 0;
        EXPECT_EQ(device.subsystem_known, endpoint_layout);
        EXPECT_EQ(device.subsystem_vendor_id, endpoint_layout ? 0x14C3u : 0u);
        EXPECT_EQ(device.subsystem_device_id, endpoint_layout ? 0xE0B6u : 0u);
    }

    // Even a type-0 header may not consume a supplied value unless the
    // hardware path explicitly records that it read the endpoint register.
    {
        const pci::Device device =
            pci::detail::DecodeDeviceIdentity(address, 0x792214C3u, 0x02000101u, 0x00000000u, 0xE0B614C3u, false);
        EXPECT_FALSE(device.subsystem_known);
        EXPECT_EQ(device.subsystem_vendor_id, 0);
        EXPECT_EQ(device.subsystem_device_id, 0);
    }

    // All-zero/all-ones subsystem vendor values are not identities. Keep the
    // tuple normalized so callers cannot accidentally match hostile residue.
    constexpr duetos::u32 invalid_subsystems[] = {0x00000000u, 0x12340000u, 0xFFFFFFFFu, 0x1234FFFFu};
    for (const duetos::u32 subsystem : invalid_subsystems)
    {
        const pci::Device device =
            pci::detail::DecodeDeviceIdentity(address, 0x792214C3u, 0x02000101u, 0x00000000u, subsystem, true);
        EXPECT_FALSE(device.subsystem_known);
        EXPECT_EQ(device.subsystem_vendor_id, 0);
        EXPECT_EQ(device.subsystem_device_id, 0);
    }

    // Subsystem device ID zero is a representable value when the vendor ID
    // is valid; `known` describes whether a trustworthy endpoint tuple was
    // read, not whether a particular backend supports it.
    {
        const pci::Device device =
            pci::detail::DecodeDeviceIdentity(address, 0x00011234u, 0xFFFEFDFCu, 0x00000000u, 0x000014C3u, true);
        EXPECT_TRUE(device.subsystem_known);
        EXPECT_EQ(device.subsystem_vendor_id, 0x14C3);
        EXPECT_EQ(device.subsystem_device_id, 0);
        EXPECT_EQ(device.class_code, 0xFF);
        EXPECT_EQ(device.subclass, 0xFE);
        EXPECT_EQ(device.programming_interface, 0xFD);
        EXPECT_EQ(device.revision_id, 0xFC);
    }

    return ::duetos_host_test::finish_main("test_pci_endpoint_identity");
}
