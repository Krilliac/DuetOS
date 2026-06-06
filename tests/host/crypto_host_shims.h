#pragma once
//
// crypto_host_shims.h — host definitions for the kernel-only symbols the
// crypto TUs (ec.cpp, bigint.cpp, rsa.cpp, x509.cpp, asn1.cpp, sha*.cpp,
// x509_verify.cpp) reference when compiled into a hosted ctest.
//
// The kernel crypto modules log via arch::SerialWrite, abort via
// core::Panic*, and fire a debug probe on a self-test failure. None of
// those exist off-target, so we define them here. SerialWrite output is
// captured in g_crypto_serial so a test can read back a self-test's own
// "[<name>-selftest] PASS / FAIL" verdict line.
//
// The shims are plain (external) definitions, not `inline`: the kernel
// crypto TUs are separate compilation units that call these symbols, so
// they must resolve to an emitted external symbol at link. Each crypto
// test is its own executable and exactly ONE of its TUs (the test_*.cpp)
// includes this header, so there is one definition per link — include it
// from a single TU per test executable.

#include "debug/probes.h"

#include <cstdio>
#include <cstdlib>
#include <string>

std::string g_crypto_serial;

namespace duetos::arch
{
void SerialWrite(const char* s)
{
    if (s != nullptr)
    {
        g_crypto_serial += s;
    }
}
void SerialWriteHex(duetos::u64 value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(value));
    g_crypto_serial += buf;
}
} // namespace duetos::arch

namespace duetos::core
{
[[noreturn]] void Panic(const char* subsystem, const char* message)
{
    std::fprintf(stderr, "PANIC %s: %s\n", subsystem ? subsystem : "?", message ? message : "?");
    std::abort();
}
[[noreturn]] void PanicWithValue(const char* subsystem, const char* message, duetos::u64 value)
{
    std::fprintf(stderr, "PANIC %s: %s (0x%llx)\n", subsystem ? subsystem : "?", message ? message : "?",
                 static_cast<unsigned long long>(value));
    std::abort();
}
} // namespace duetos::core

namespace duetos::debug
{
// A self-test failure fires this probe before returning; tests detect
// failure via the captured "FAIL" line, so the shim is a no-op.
void ProbeFire(ProbeId, duetos::u64, duetos::u64) {}
} // namespace duetos::debug
