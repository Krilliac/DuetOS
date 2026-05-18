#pragma once

#include "acpi/aml.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — AML method interpreter (v0).
 *
 * Companion to the namespace walker in aml.{h,cpp}. The walker
 * indexes every Name / Method / OperationRegion / FieldUnit by
 * canonical path; THIS file actually *executes* a method body.
 *
 * Scope (what real firmware needs on the laptop driver path):
 *   - Object model: Integer (u64), Buffer, String, Package.
 *   - Operands: Arg0-6, Local0-7, constants, Buffer, Package,
 *     NameString refs (Name read, FieldUnit read/write, nested
 *     Method call).
 *   - Arithmetic / bitwise / logical ops with optional Target.
 *   - Control flow: If / Else / While / Return / Break / Continue.
 *   - Store / CopyObject / DerefOf / RefOf / Index / SizeOf /
 *     ObjectType / Match / Mid / Concatenate / To{Integer,Buffer,
 *     String,HexString,DecimalString} / FindSet{Left,Right}Bit.
 *   - Sleep / Stall / Acquire / Release / Notify / Noop.
 *   - OperationRegion access for SystemIO, SystemMemory, PCI_Config
 *     directly; EmbeddedControl / SMBus via a registered handler
 *     (the EC driver plugs in here in a later slice).
 *
 * GAPs (marked, bounded — see aml_eval.cpp):
 *   - Buffer / String capped at kAmlBufCap bytes.
 *   - Package capped at kAmlPkgCap elements; nesting via a fixed
 *     per-evaluation arena (kAmlArenaCap nodes).
 *   - Regions with computed (non-constant) offset/length are not
 *     indexed, so fields inside them read back as Ones.
 *
 * Context: kernel, process context only (Stall/Sleep busy-wait on
 * the monotonic clock; never call from IRQ context).
 */

namespace duetos::acpi
{

inline constexpr u32 kAmlBufCap = 256;  // Buffer / String byte cap
inline constexpr u16 kAmlPkgCap = 32;   // elements per Package
inline constexpr u32 kAmlArenaCap = 96; // AmlValue nodes per evaluation

enum class AmlType : u8
{
    Uninit,
    Integer,
    String,
    Buffer,
    Package,
};

// A value. Buffer/String share `bytes`/`len`. Package elements live
// in the evaluation arena; `pkg_first` is the arena index of element
// 0 and `pkg_count` the count. Trivially copyable (no owning ptrs) —
// the arena outlives every AmlValue produced during one evaluation.
struct AmlValue
{
    AmlType type = AmlType::Uninit;
    u8 _pad[1] = {};
    u16 pkg_count = 0;
    u16 pkg_first = 0;
    u16 len = 0;
    u64 integer = 0;
    u8 bytes[kAmlBufCap] = {};

    static AmlValue Int(u64 v)
    {
        AmlValue x;
        x.type = AmlType::Integer;
        x.integer = v;
        return x;
    }
};

// Region-space backend. The interpreter calls this for any region
// space it doesn't service directly (EmbeddedControl, SMBus, CMOS).
// `write` selects direction; on a read `*value` receives the result.
// `width_bits` is 8/16/32/64. Return false → the access fails and
// the field reads back as Ones / a write is dropped.
using AmlRegionHandler = bool (*)(void* ctx, bool write, u64 address, u32 width_bits, u64* value);

// Register a handler for one region space (e.g. EmbeddedControl).
// Idempotent per space; last registration wins. `ctx` is passed
// back verbatim.
void AmlRegisterRegionHandler(AmlRegionSpace space, AmlRegionHandler handler, void* ctx);

// Evaluate the method (or read the Name) at canonical `path`,
// passing `argc` arguments (≤ 7). On success `*out` holds the
// return value (Uninit if the method returned nothing).
::duetos::core::Result<void> AmlEvaluate(const char* path, const AmlValue* args, u32 argc, AmlValue* out);

// Convenience: evaluate and coerce the result to an integer.
// Returns false if the path is missing, evaluation failed, or the
// result is not integer-coercible.
bool AmlEvaluateInteger(const char* path, u64* out, const AmlValue* args = nullptr, u32 argc = 0);

// Run a raw method-body TermList directly (used by the boot
// self-test to exercise the interpreter on synthetic bytecode
// without depending on firmware DSDT contents). `aml`/`len`
// bracket the TermList; `args`/`argc` seed Arg0..ArgN.
::duetos::core::Result<void> AmlEvaluateRaw(const u8* aml, u32 len, const AmlValue* args, u32 argc, AmlValue* out);

// Boot self-test: drives AmlEvaluateRaw over a handful of synthetic
// programs (arithmetic, If/Else, While, nested-call shape, Store to
// Local, Package build) and panics on a wrong result. Emits one
// `[acpi/aml-eval] selftest PASS` line. No init side effects.
void AmlEvalSelfTest();

} // namespace duetos::acpi
