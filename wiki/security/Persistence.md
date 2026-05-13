# Persistence — secrets at rest

> **Audience:** RBAC + auth implementers, installer authors, TPM driver authors
>
> **Execution context:** Kernel (read/write) + boot installer (write-only first-boot path)
>
> **Maturity:** v0 — design only. Code currently re-seeds defaults on every boot.

## What problem this solves

The kernel today seeds two hardcoded accounts (`admin / admin`,
`guest / ""`) at every `AuthInit()` and bakes the role + membership
tables in memory at every `RbacInit()`. Anything added or changed at
runtime (`useradd`, `roleadd`, `passwd`) is lost on reboot. Without
persistence:

- The first-time-user UX is "log in as `admin / admin`" — which is
  the canonical default-credential vulnerability every threat model
  treats as game over.
- Operators can't add real accounts. Every reboot wipes the table.
- There's no plausible deployment story past "demo VM."

This page documents the design for the secrets-at-rest layer that
fixes all of that.

## Threat model

Adversaries we're defending against:

1. **Offline attacker holding the disk image.** The most common
   compromise vector. Mitigation: every credential record is
   stored under an Argon2id-derived KEK; the KEK is wrapped by a
   TPM-sealed key.
2. **Untrusted local user with read access to a system partition.**
   Defense: same KEK protection + filesystem ACLs that deny
   non-root read of `/system/secrets`.
3. **Online attacker who has compromised a user-space process.**
   Defense: kernel-mediated capability gating
   (`wiki/security/Capabilities.md`); user-space cannot read raw
   secrets even with stdio/fs access.

Out of scope:
- Defense against a kernel-mode adversary. Once they're in the
  kernel they hold every cap; secrets at rest are moot.
- Defense against a hardware adversary with cold-boot DRAM
  capture. We can't beat that without ARM TrustZone or AMD SEV-SNP.

## On-disk layout

```
/system/secrets/
    accounts.duet      — encrypted account table (auth.cpp records)
    roles.duet         — encrypted role table (rbac.cpp records)
    memberships.duet   — encrypted user→role bindings
    kek.sealed         — TPM-sealed KEK wrap (only when TPM driver lands)
    header.duet        — format version + KDF params + wrap algorithm
```

Each `*.duet` file has the same envelope:

```
struct DuetSecretsFile {
    u8 magic[4];            // 'D','S','E','C'
    u32 format_version;     // = 1 today
    u32 record_count;
    u32 record_size;        // bytes per record (locked at write time)
    u8 nonce[12];           // ChaCha20-Poly1305 nonce
    u8 ciphertext[record_count * record_size];
    u8 mac[16];             // Poly1305 tag over header + ciphertext
};
```

ChaCha20-Poly1305 (RFC 8439) is the AEAD. The kernel already has
SHA-256 and HMAC; ChaCha20-Poly1305 is the natural next primitive
to land for at-rest encryption.

## KEK derivation

```
KEK = Argon2id(
    password=user_password,
    salt=16_byte_per_install_salt,
    memory=64_MiB,             # production target; 4_MiB in emulator
    time_cost=3,
    parallelism=1,
    output=32_bytes
)
```

The salt is generated once at first-boot install, stored in
`header.duet` (in cleartext — salts are not secret). Production
memory is 64 MiB; the emulator profile drops to 4 MiB so QEMU
boot stays fast.

When TPM driver lands: a random 32-byte session key encrypts the
account/role files; the KEK derived from the user password wraps
the session key; the wrap is TPM-sealed to PCR 0..7. Operators who
swap the disk into a different machine see "sealed wrap mismatch"
and can choose to re-key with the recovery password.

## Record format V2 (in-kernel)

```c
struct PasswordHashRecordV2 {
    u32 version;      // = 2
    u32 algorithm;    // 1 = PBKDF2-HMAC-SHA256, 2 = Argon2id
    u8 salt[16];
    u8 hash[32];      // tag
    union {
        struct { u32 iterations; u32 reserved[3]; } pbkdf2;
        struct { u32 memory_kib; u32 time_cost; u32 parallelism; u32 reserved; } argon2id;
    } params;
};
// total: 72 bytes
```

V1 records (56 bytes, PBKDF2 only) round up to V2 on the next
successful verify — see *Lazy migration* below.

## Lazy migration

`AuthVerify` reads the record's algorithm tag and runs the matching
KDF. On a successful PBKDF2 verify, the kernel re-hashes the
plaintext password with Argon2id (using current per-install params)
and writes a fresh V2 record over the old V1 slot. The user notices
nothing; the on-disk record gets stronger silently.

Both code paths run a full derivation regardless of which kind
wins, so the verify wall-clock is uniform across "user not found
/ user found, wrong password / user found, right password" and
also uniform across "old V1 record / new V2 record." The existing
decoy-record machinery in `auth.cpp` already handles the
not-found branch; the migration just adds another timing-uniform
arm.

## First-boot installer

When `/system/secrets/header.duet` doesn't exist, the kernel
boots into installer mode:

1. Prompt for an admin username + password (kernel-trusted prompt,
   same path as the elevation broker).
2. Generate the per-install salt and the random session key.
3. Argon2id-derive the KEK from the password + salt.
4. Wrap the session key under the KEK; write `header.duet` + the
   empty account/role/membership files.
5. Seed the `root` membership for the admin account.
6. Reboot into normal mode.

The wizard runs in user-mode (`userland/init/installer`) and uses
the same kernel APIs (`AuthAddUser`, `RbacAddMembership`) the
shell uses today.

## What's wired up today

| Surface                              | State                                                                  |
|--------------------------------------|------------------------------------------------------------------------|
| Blake2b primitive                    | REAL — `kernel/security/blake2b.{h,cpp}`, KAT-verified                 |
| Argon2id                             | REAL — `kernel/security/argon2id.{h,cpp}`, RFC 9106 §5.3 KAT-verified  |
| `PasswordHashRecordV2`               | REAL — Argon2id is now the V2 default; PBKDF2 retained for migration   |
| ChaCha20-Poly1305 AEAD               | REAL — `kernel/security/chacha20_poly1305.{h,cpp}`, RFC 8439 §2.8.2 KAT |
| `DuetSecretsFile` envelope           | REAL — `kernel/security/persistence.{h,cpp}`, round-trip + tamper KATs |
| `AuthExportSnapshot` / Import        | REAL — `kernel/security/auth.{h,cpp}`, boot self-test pins the path    |
| `/system/secrets/` layout (on FS)    | MISSING — no writable system FS yet (next dependent slice)             |
| Installer flow                       | MISSING — needs the writable FS                                        |
| TPM sealing                          | MISSING — blocks on TPM driver                                         |

The cryptographic + serialisation layers are complete and exercised
at every boot via the security self-test sequence. The remaining
work is plumbing — pointing the existing `Auth{Export,Import}Snapshot`
calls at a writable `/system/secrets/accounts.duet` instead of a
caller-supplied buffer. That requires the writable-FS slice landing
first; the API contract is already pinned and will not change shape.

## Dependency order

```
1. Argon2id  (Blake2b foundation already shipping)        — DONE
2. PasswordHashRecordV2 + Argon2id default                — DONE
3. ChaCha20-Poly1305 (AEAD for the on-disk envelope)      — DONE
4. DuetSecretsFile envelope + Auth snapshot API           — DONE
5. Writable system FS partition + /system/secrets/ mount  — pending
6. First-boot installer flow                              — pending
7. (later) TPM driver + KEK sealing                       — pending
```

Steps 1–4 land in this slice. The remaining steps depend on the
writable-FS work being scheduled before the secrets directory can
have a physical home.

## Related pages

- [RBAC and Elevation](RBAC-and-Elevation.md)
- [Capabilities](Capabilities.md)
- [VFS](../filesystem/VFS.md)
