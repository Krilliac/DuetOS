// DuetOS — USB RNDIS class-driver parser fuzz harness.
//
// RndisProbe (kernel/drivers/usb/rndis.cpp) brings a Microsoft-RNDIS
// USB-Ethernet device online through two attacker-controlled parse
// surfaces, both fuzzed here:
//   1. GET_DESCRIPTOR(Config) -> RndisParseConfig — the
//      configuration / interface / endpoint walker that locates the
//      comm interface + bulk pair.
//   2. The RNDIS control channel: SEND/GET_ENCAPSULATED_RESPONSE ->
//      RndisInitialize (INITIALIZE_CMPLT), RndisSetU32Oid (SET_CMPLT)
//      and RndisQueryMac (QUERY_CMPLT). RndisQueryMac is the classic
//      length/offset spot — it reads the MAC at
//      `8 + InformationBufferOffset` after an InformationBufferLength
//      / Offset containment check.
//
// host_shim/usbnet_stubs.cpp serves the libFuzzer input as the stream
// of control-IN replies the bring-up sequence consumes in order, so
// the real walkers + reply parsers run on fuzzed bytes (the fuzz_aml
// model). ASan/UBSan guard the offset arithmetic.
//
// NOT reached: the rndis-rx bulk deframer (a `for (;;)` task the
// stubbed SchedCreate never starts). That loop is the OTHER classic
// length/offset OOB site (MessageLength vs DataOffset + DataLength
// containment); a u32-wrap OOB read found there while writing this
// harness was fixed in rndis.cpp (see RxPollEntry). Making the
// deframer body fuzzable would need a small kernel seam extracting it
// from the task loop — out of scope for this harness.

#include "drivers/usb/rndis.h"

#include <cstddef>
#include <cstdint>

extern "C" void UsbnetFuzzFeed(const uint8_t* data, uint32_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 4096)
        return 0;

    UsbnetFuzzFeed(data, static_cast<uint32_t>(size));
    (void)duetos::drivers::usb::RndisProbe();
    return 0;
}
