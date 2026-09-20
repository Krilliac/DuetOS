// Hosted contract for DRSH desktop input payload decoding.

#include "host_test_helper.h"

#include "net/drsh/drsh_desktop_wire.h"

int main()
{
    using namespace duetos::net::drsh::desktop_wire;

    {
        const duetos::u8 payload[] = {kInputKey, 0x41, 0x00, 0x05, 0x01};
        KeyInput decoded{};
        EXPECT_TRUE(DecodeKeyInput(payload, sizeof(payload), &decoded));
        EXPECT_EQ(decoded.code, 0x0041U);
        EXPECT_EQ(decoded.modifiers, 0x05U);
        EXPECT_TRUE(decoded.pressed);
    }

    {
        const duetos::u8 payload[] = {kInputKey, 0x00, 0x01, 0x02, 0x00};
        KeyInput decoded{};
        EXPECT_TRUE(DecodeKeyInput(payload, sizeof(payload), &decoded));
        EXPECT_EQ(decoded.code, 0x0100U);
        EXPECT_EQ(decoded.modifiers, 0x02U);
        EXPECT_FALSE(decoded.pressed);
    }

    {
        const duetos::u8 short_payload[] = {kInputKey, 0x41, 0x00, 0x00};
        KeyInput decoded{};
        EXPECT_FALSE(DecodeKeyInput(short_payload, sizeof(short_payload), &decoded));
        EXPECT_FALSE(DecodeKeyInput(nullptr, 0, &decoded));
        EXPECT_FALSE(DecodeKeyInput(short_payload, sizeof(short_payload), nullptr));
    }

    {
        const duetos::u8 native[] = {1};
        DesktopOpenRequest request{};
        EXPECT_TRUE(DecodeOpenRequest(native, sizeof(native), &request));
        EXPECT_EQ(request.width, 0U);
        EXPECT_EQ(request.height, 0U);

        const duetos::u8 scaled[] = {1, 0x01, 0x00, 0x00, 0xC0};
        EXPECT_TRUE(DecodeOpenRequest(scaled, sizeof(scaled), &request));
        EXPECT_EQ(request.width, 256U);
        EXPECT_EQ(request.height, 192U);

        const duetos::u8 zero_width[] = {1, 0x00, 0x00, 0x00, 0xC0};
        EXPECT_FALSE(DecodeOpenRequest(zero_width, sizeof(zero_width), &request));
        EXPECT_FALSE(DecodeOpenRequest(native, 0, &request));
    }

    EXPECT_EQ(ScaleCoordinate(0, 256, 1024), 0U);
    EXPECT_EQ(ScaleCoordinate(255, 256, 1024), 1023U);
    EXPECT_EQ(ScaleCoordinate(256, 256, 1024), 1023U);
    EXPECT_EQ(ScaleCoordinate(999, 256, 1024), 1023U);
    EXPECT_EQ(ScaleCoordinate(1, 1, 1024), 0U);

    EXPECT_TRUE(FitsWireDimensions(1024, 768));
    EXPECT_TRUE(FitsWireDimensions(65535, 65535));
    EXPECT_FALSE(FitsWireDimensions(0, 768));
    EXPECT_FALSE(FitsWireDimensions(65536, 768));

    EXPECT_EQ(MouseDeltaStep(0), 0);
    EXPECT_EQ(MouseDeltaStep(127), 127);
    EXPECT_EQ(MouseDeltaStep(128), 127);
    EXPECT_EQ(MouseDeltaStep(-128), -128);
    EXPECT_EQ(MouseDeltaStep(-129), -128);

    return ::duetos_host_test::finish_main("tests/host/test_drsh_desktop_wire.cpp");
}
