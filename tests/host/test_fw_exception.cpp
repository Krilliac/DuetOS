// Hosted tests for firewall exception spec parsing.
//
// A firewall exception punches a hole in the packet filter, so the
// parser is fail-closed by design: anything it does not fully
// understand is rejected outright rather than partially applied. A
// half-parsed spec would be a hole of unknown shape, which is worse
// than no exception at all. These tests pin both halves — the specs
// that must work, and the malformed ones that must not.

#include "host_test_helper.h"
#include "net/fw_exception.h"

using duetos::u32;
using duetos::net::firewall::ExceptionSpec;
using duetos::net::firewall::ParseExceptionSpec;

namespace
{

bool Parse(const char* s, ExceptionSpec* out)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return ParseExceptionSpec(s, n, out);
}

void ExpectRejected(const char* s, const char* why)
{
    ExceptionSpec spec{};
    const bool ok = Parse(s, &spec);
    if (ok)
    {
        std::fprintf(stderr, "FAIL: spec \"%s\" was accepted but should be rejected (%s)\n", s, why);
        ++duetos_host_test::failure_count();
    }
}

void TestAccepted()
{
    ExceptionSpec spec{};

    EXPECT_TRUE(Parse("in:tcp:10.0.2.2/32:8080", &spec));
    EXPECT_TRUE(!spec.egress);
    EXPECT_EQ(spec.proto, 6u);
    EXPECT_EQ(spec.addr[0], 10u);
    EXPECT_EQ(spec.addr[2], 2u);
    EXPECT_EQ(spec.addr[3], 2u);
    EXPECT_EQ(spec.mask_bits, 32u);
    EXPECT_TRUE(!spec.any_port);
    EXPECT_EQ(spec.port, 8080u);

    EXPECT_TRUE(Parse("out:udp:0.0.0.0/0:53", &spec));
    EXPECT_TRUE(spec.egress);
    EXPECT_EQ(spec.proto, 17u);
    EXPECT_EQ(spec.mask_bits, 0u);
    EXPECT_EQ(spec.port, 53u);

    EXPECT_TRUE(Parse("in:icmp:192.168.1.0/24:*", &spec));
    EXPECT_EQ(spec.proto, 1u);
    EXPECT_EQ(spec.addr[0], 192u);
    EXPECT_EQ(spec.mask_bits, 24u);
    EXPECT_TRUE(spec.any_port);

    EXPECT_TRUE(Parse("in:any:255.255.255.255/32:*", &spec));
    EXPECT_EQ(spec.proto, 0u);
    EXPECT_EQ(spec.addr[3], 255u);

    // Boundary ports.
    EXPECT_TRUE(Parse("in:tcp:1.2.3.4/32:0", &spec));
    EXPECT_EQ(spec.port, 0u);
    EXPECT_TRUE(!spec.any_port);
    EXPECT_TRUE(Parse("in:tcp:1.2.3.4/32:65535", &spec));
    EXPECT_EQ(spec.port, 65535u);
}

void TestRejected()
{
    // Field count.
    ExpectRejected("", "empty");
    ExpectRejected("in:tcp:10.0.2.2/32", "missing port field");
    ExpectRejected("in:tcp:10.0.2.2/32:80:extra", "extra field");
    ExpectRejected("in:tcp", "far too few fields");

    // Direction.
    ExpectRejected("ingress:tcp:10.0.2.2/32:80", "unknown direction word");
    ExpectRejected("IN:tcp:10.0.2.2/32:80", "direction is case-sensitive");
    ExpectRejected(":tcp:10.0.2.2/32:80", "empty direction");

    // Protocol. An unrecognised protocol must not fall back to
    // "any" — that would silently widen the hole.
    ExpectRejected("in:sctp:10.0.2.2/32:80", "unknown protocol");
    ExpectRejected("in:6:10.0.2.2/32:80", "numeric protocol not accepted");
    ExpectRejected("in::10.0.2.2/32:80", "empty protocol");

    // Address / mask.
    ExpectRejected("in:tcp:10.0.2.2:80", "missing /mask");
    ExpectRejected("in:tcp:10.0.2.2/33:80", "mask above 32");
    ExpectRejected("in:tcp:10.0.2/32:80", "three octets");
    ExpectRejected("in:tcp:10.0.2.2.5/32:80", "five octets");
    ExpectRejected("in:tcp:10.0.2.256/32:80", "octet above 255");
    ExpectRejected("in:tcp:10.0.2.x/32:80", "non-numeric octet");
    ExpectRejected("in:tcp:10.0.2.2//32:80", "empty mask between slashes");
    ExpectRejected("in:tcp:10.0.2.2/32/8:80", "two slashes");
    ExpectRejected("in:tcp:10.0..2/32:80", "empty octet");

    // Port.
    ExpectRejected("in:tcp:10.0.2.2/32:70000", "port above 65535");
    ExpectRejected("in:tcp:10.0.2.2/32:", "empty port");
    ExpectRejected("in:tcp:10.0.2.2/32:http", "non-numeric port");
    ExpectRejected("in:tcp:10.0.2.2/32:-1", "negative port");

    // ICMP has no ports; an explicit one means the operator has
    // misunderstood the rule they are writing.
    ExpectRejected("in:icmp:10.0.2.2/32:8", "explicit port on ICMP");
}

void TestNoPartialWrite()
{
    // A rejected spec must leave the caller's struct untouched: the
    // firewall builds a Rule straight from it, so a half-filled spec
    // would install a rule nobody described.
    ExceptionSpec spec{};
    spec.proto = 99;
    spec.mask_bits = 7;
    spec.port = 1234;
    EXPECT_TRUE(!Parse("in:tcp:10.0.2.2/32:70000", &spec));
    EXPECT_EQ(spec.proto, 99u);
    EXPECT_EQ(spec.mask_bits, 7u);
    EXPECT_EQ(spec.port, 1234u);

    // Null out-param and null input are both rejected, not crashed.
    EXPECT_TRUE(!ParseExceptionSpec("in:tcp:1.2.3.4/32:80", 20, nullptr));
    EXPECT_TRUE(!ParseExceptionSpec(nullptr, 20, &spec));
    EXPECT_TRUE(!ParseExceptionSpec("in:tcp:1.2.3.4/32:80", 0, &spec));
}

} // namespace

int main()
{
    TestAccepted();
    TestRejected();
    TestNoPartialWrite();
    return duetos_host_test::finish_main("fw_exception");
}
