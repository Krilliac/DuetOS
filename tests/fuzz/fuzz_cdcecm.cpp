// DuetOS — USB CDC-ECM class-driver parser fuzz harness.
//
// CdcEcmProbe (kernel/drivers/usb/cdc_ecm.cpp) brings a USB-Ethernet
// device online by GET_DESCRIPTOR(Config) -> ParseConfigDescriptor
// (the configuration / interface / endpoint + CDC Ethernet
// Functional Descriptor walker) and GET_DESCRIPTOR(String) ->
// ReadMacFromString (the 12-char ASCII-hex iMACAddress parser).
// Every byte those two walkers touch comes from the peripheral's
// control-IN responses — fully attacker-controlled for a hostile /
// BadUSB device. host_shim/usbnet_stubs.cpp serves the libFuzzer
// input as the stream of control-IN replies, so the real walkers run
// on fuzzed bytes; ASan catches any OOB read past a descriptor
// bound, UBSan any sign/overflow in the length math.
//
// The probe's one-frame DMA pool (see usbnet_stubs.cpp) makes the
// rx/tx allocation pair fail just after the parsers run, so BringUp
// returns false before it latches the driver's file-local "online"
// flag — every input re-exercises the parsers from clean state.
//
// NOT reached: the cdc-ecm-rx bulk poll loop (a `for (;;)` task the
// stubbed SchedCreate never starts). CDC-ECM's RX path injects the
// raw transfer verbatim (no per-frame length/offset arithmetic), so
// the descriptor + string parsers above are its entire untrusted
// pre-net-stack parse surface.

#include "drivers/usb/cdc_ecm.h"

#include <cstddef>
#include <cstdint>

extern "C" void UsbnetFuzzFeed(const uint8_t* data, uint32_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // The driver caps a sane config descriptor at 1 KiB; a little
    // headroom keeps truncated/oversize reply paths reachable.
    if (size > 4096)
        return 0;

    UsbnetFuzzFeed(data, static_cast<uint32_t>(size));
    (void)duetos::drivers::usb::CdcEcmProbe();
    return 0;
}
