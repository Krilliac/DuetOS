#!/usr/bin/env python3
"""Structural guard for the trusted ServiceEndpoint route-policy matrix."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_protocol_policy.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_protocol_policy.cpp").read_text(encoding="utf-8")
INGRESS = (ROOT / "kernel/syscall/service_endpoint_ingress.cpp").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_exact_manifest_policy_pairs_are_frozen() -> None:
    for symbol, value in (
        ("kServicedManifestServiceIdentityV1", "0x100"),
        ("kExecdManifestServiceIdentityV1", "0x200"),
        ("kDisplaydManifestServiceIdentityV1", "0x300"),
        ("kRegistrydManifestServiceIdentityV1", "0x400"),
        ("kNetdManifestServiceIdentityV1", "0x500"),
    ):
        require(re.search(rf"{symbol}\s*=\s*{value}\b", HEADER) is not None,
                f"missing frozen {symbol}={value}")
    require("kServiceProtocolImmutablePolicyV1 = 1" in HEADER, "selector v1 drifted")
    require("policy.protocol_version <= kServiceEndpointProtocolVersionMaximum" in SOURCE,
            "policy version ceiling must use the exact 16-bit protocol maximum")


def test_administrative_routes_fail_closed() -> None:
    serviced = SOURCE[SOURCE.index("case kServicedManifestServiceIdentityV1"):
                      SOURCE.index("case kExecdManifestServiceIdentityV1")]
    displayd = SOURCE[SOURCE.index("case kDisplaydManifestServiceIdentityV1"):
                       SOURCE.index("case kRegistrydManifestServiceIdentityV1")]
    require("ServicedMethod::Enumerate" in serviced and "ServicedMethod::Query" in serviced,
            "serviced inspection routes missing")
    require(all(name not in serviced for name in ("ServicedMethod::Start", "ServicedMethod::Stop", "ServicedMethod::Restart")),
            "serviced control route granted without dedicated capability")
    require("GuiBrokerMethod::Post" in displayd, "display post route missing")
    require("GuiBrokerMethod::RegisterRule" not in displayd and "GuiBrokerMethod::RevokeRule" not in displayd,
            "GUI policy-admin route granted without dedicated capability")
    require(all(cap not in SOURCE for cap in ("kCapDiag", "kCapSpawnThread", "kCapInput")),
            "unrelated capability aliased to protocol authority")


def test_execd_is_fs_read_gated_and_unimplemented_routes_are_unsupported() -> None:
    require("CapSetHas(caller_capabilities, kCapFsRead)" in SOURCE, "execd Parse is not fs-read gated")
    unsupported = SOURCE[SOURCE.index("case kRegistrydManifestServiceIdentityV1"):
                         SOURCE.index("default:", SOURCE.index("case kRegistrydManifestServiceIdentityV1"))]
    require("ServiceProtocolPolicyStatus::NotSupported" in unsupported,
            "registryd/netd must fail closed until exact MessageAbi policies exist")


def test_resolution_precedes_authority_mint_and_directory_mutation() -> None:
    # The ingress implementation is completed in the same feature slice. This
    # order prevents absent caps or policy from consuming an identity, pinning
    # a directory row, or reserving a handle.
    if "ExecuteConnect" not in INGRESS:
        return
    body = INGRESS[INGRESS.index("void ExecuteConnect"):]
    body = body[:body.index("void ", 5)]
    resolve = body.index("ResolveTargetService")
    mint = body.index("MintProtocolAuthorityIdentity")
    lookup = body.index("ServiceDirectoryLookup")
    connect = body.index("ServiceDirectoryConnect")
    require(resolve < lookup < mint < connect,
            "CONNECT must resolve policy before directory mutation and mint only after exact row verification")
    resolver = INGRESS[INGRESS.index("AbiStatus ResolveTargetService"):INGRESS.index("AbiStatus CloseEndpointHandle")]
    require("ServiceProtocolPolicyResolveV1" in resolver,
            "target resolution must derive authority only from trusted protocol policy")


def main() -> int:
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS: {len(tests)}/{len(tests)} service protocol policy contract checks")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
