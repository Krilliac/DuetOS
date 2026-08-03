#pragma once

/*
 * Size/version-tagged payload contract for generated IPC request, reply, and
 * notification structures.
 *
 * The eight-byte little-endian prefix is part of every typed payload:
 *
 *   u32 total_size;  // exact payload size, including this prefix
 *   u16 version;
 *   u16 flags;
 *
 * Generated IDL code supplies a small, strictly version-ordered rule table.
 * Validation consumes an immutable kernel-owned snapshot of the hostile bytes
 * and an immutable trusted rule table.  They must be disjoint, and the payload
 * snapshot must remain unchanged through every downstream body read authorized
 * by the returned scalar view.  This layer performs no allocation, locking,
 * blocking, logging, copying, or authorization.  Authority remains attached
 * to the retained IPC endpoint.
 */

#include "ipc/message_abi.h"
#include "util/types.h"

namespace duetos::ipc
{

inline constexpr u32 kVersionedPayloadHeaderBytes = 8;
inline constexpr u32 kVersionedPayloadMaxBytes = kMessageAbiMaxBytes - kMessageAbiHeaderV1Bytes;

// Bounds runtime work even if a corrupted or handwritten caller supplies the
// metadata table.  Generated service contracts are expected to be far smaller.
inline constexpr u32 kVersionedPayloadMaxRules = 256;

struct PayloadVersionRule
{
    u16 version;
    u16 known_flags;
    u32 minimum_size;
    u32 maximum_size;
};

enum class PayloadValidationError : u8
{
    Ok = 0,
    NullBuffer = 1,
    InvalidRuleTable = 2,
    TruncatedHeader = 3,
    PayloadTooSmall = 4,
    PayloadTooLarge = 5,
    SizeMismatch = 6,
    UnsupportedVersion = 7,
    UnsupportedFlags = 8,
    SizeOutsideVersionRange = 9,
    OutputAliasesInput = 10,
    InputsOverlap = 11,
};

struct VersionedPayloadView
{
    u32 total_size;
    u16 version;
    u16 flags;
};

/// Encode a canonical payload prefix without touching bytes after the prefix.
/// The supplied rule table must be strictly increasing by nonzero version and
/// every rule must describe a valid range.  Any failure leaves `buffer`
/// unchanged.  `rules` may overlap `buffer`; the matching rule is snapshotted
/// before the first store.
PayloadValidationError PayloadEncodeHeader(void* buffer, u32 buffer_bytes, u16 version, u16 flags,
                                           const PayloadVersionRule* rules, u32 rule_count);

/// Validate one complete immutable typed-payload snapshot against an immutable
/// generated rule table.  The encoded total must exactly match
/// `available_bytes`; the snapshot must remain unchanged until all downstream
/// body decoding completes.  The payload, rule table, and optional `view_out`
/// storage must be pairwise disjoint.  Alias failures and a `rule_count` too
/// large to establish a bounded input extent leave all storage unchanged;
/// after those preflight checks, `view_out` is zeroed before any failure is
/// returned.  Payload buffers may be unaligned.
PayloadValidationError PayloadValidate(const void* buffer, u32 available_bytes, const PayloadVersionRule* rules,
                                       u32 rule_count, VersionedPayloadView* view_out);

/// Stable diagnostic spelling for payload validation results.
const char* PayloadValidationErrorName(PayloadValidationError error);

} // namespace duetos::ipc
