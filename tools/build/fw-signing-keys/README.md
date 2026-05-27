# DuetOS firmware-signing dev keys

This directory holds the **development** RSA-2048 keypair used by
`tools/build/fw-sign.py` to sign DuetOS firmware packages
(DUETFWPK envelopes) so the kernel's trust-root verify path
(`FwPackageVerifySignature`) can be exercised in tree without
external infrastructure.

## ⚠️ DO NOT USE THIS KEYPAIR IN PRODUCTION

`dev-fw-signing-private.pem` is committed in plaintext to the
public repository. The matching public key is baked into the
kernel as `kFwTrustRootModulusBE` in
`kernel/loader/firmware_package_trust.h`. Anyone with read access
to this repository can sign packages the in-tree kernel will
accept. **This is intentional for dev builds; it is fatal for
production.**

A production deployment MUST replace this key with one whose
private half is held offline (HSM, signing CI, etc.). The
mechanism is:

1. Generate a fresh RSA-2048 keypair offline.
2. Export the public-key modulus / exponent as big-endian byte
   arrays.
3. Either (a) replace `kFwTrustRootModulusBE` + `kFwTrustRootExponentBE`
   directly in `kernel/loader/firmware_package_trust.h`, or
   (b) point CMake at an alternate trust-root header via
   `-DDUETOS_FW_TRUST_ROOT_HEADER=path/to/alt-trust.h` (planned —
   not yet wired).
4. Re-bake the test fixture with `python3 tools/build/fw-sign.py
   --emit-test-fixture --key /path/to/prod-key > \
   kernel/loader/firmware_package_test_vectors.h` so the in-tree
   self-test still verifies against the new key.

The dev key in this directory is the *only* trust root recognized
by the upstream kernel today. Production builds should set
`DUETOS_FW_REQUIRE_SIGNATURE=1` so unsigned packages are refused
at parse time.

## Regenerating the dev keypair

If you need to re-roll the dev key (key compromise, format change),
the procedure is:

```bash
cd tools/build/fw-signing-keys
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open("dev-fw-signing-private.pem","wb").write(
    k.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
open("dev-fw-signing-public.pem","wb").write(
    k.public_key().public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo))
PY
```

Then re-derive the kernel constants by reading the new
`dev-fw-signing-public.pem` and emitting the `kFwTrustRootModulusBE`
/ `kFwTrustRootExponentBE` arrays. Finally:

```bash
python3 tools/build/fw-sign.py --emit-test-fixture \
  > kernel/loader/firmware_package_test_vectors.h
```

…and rebuild. The in-tree self-test verifies against the new
pubkey on the next boot.

## Threat model

Without the signature gate, an attacker with file-write access
to the firmware staging directory can swap a benign firmware
package for one with a NOP-sled-laden payload and a recomputed
SHA-256 digest. The kernel's existing integrity check (payload
digest matches header field) accepts this — the digest is a
self-consistency check, not authentication.

The trust-root signature converts that self-consistency check
into an authenticity check: only the holder of the matching
private key can produce a signature the kernel verifies. The
attacker can still corrupt the file (causing parse failure),
but they cannot substitute a different functioning payload.

What this does **not** defend against:
- Pre-tampered firmware that arrived on the storage device or
  inside a peripheral's on-board flash (covered by Secure Boot
  + IOMMU, separate slices).
- Compromise of the offline signing key.
- Bug in the verify path itself — the path is in-kernel C++
  on top of `crypto::RsaPkcs1V15Verify` which still does its
  own constant-time-ish padding decode. Treat all of this as
  attack surface and audit accordingly.
