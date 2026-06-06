// DuetOS — EC public-key (SEC1 point) parser fuzz harness.
//
// ParsePublicKey (kernel/net/ec.cpp) decodes an uncompressed EC point
// (SEC1 `0x04 || X || Y`) out of an X.509 certificate's
// SubjectPublicKeyInfo BIT STRING — reached from
// x509_verify.cpp:VerifyChain when a TLS server presents an
// ECDSA/ECDH certificate. The bytes are fully attacker-controlled:
// any TLS peer (or a cert in a chain) chooses the prefix, the
// coordinate lengths, and the coordinate values. The parser splits
// the buffer into two field-width big-integers, range-checks each
// against the field prime, and runs the on-curve test — bigint
// arithmetic over attacker-chosen inputs is the interesting TCB.
//
// The harness drives both supported curves (P-256, P-384) on every
// input so one corpus covers both field widths. ASan catches any OOB
// read on the point buffer or inside the bigint coordinate import;
// UBSan catches overflow in the field-width / length math.

#include "net/ec.h"

#include "debug/probes.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>

// ec.cpp's boot self-test fires KBP_PROBE_V on a failed sub-check; the
// harness never runs the self-test, so a no-op ProbeFire satisfies the
// link (same role as host_shim/net_stubs.cpp's stub).
namespace duetos::debug
{
void ProbeFire(ProbeId, u64, u64) {}
} // namespace duetos::debug

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // A SEC1 uncompressed P-384 point is 97 bytes; nothing larger is
    // a valid key, so cap well above that to keep the parse cheap.
    if (size > 4096)
        return 0;

    const auto* point = reinterpret_cast<const duetos::u8*>(data);
    const auto len = static_cast<duetos::u32>(size);

    using namespace duetos::net::ec;

    // Resolve the domain parameters once per input (cheap; the heavy
    // bigint work is the on-curve test inside ParsePublicKey).
    for (CurveId id : {CurveId::P256, CurveId::P384})
    {
        Curve curve{};
        if (!GetCurve(id, &curve))
            continue;
        Point out{};
        (void)ParsePublicKey(curve, point, len, &out);
    }
    return 0;
}
