# Security Exceptions

Two gates in DuetOS can refuse something an operator actually wants: the
**image guard** (`kernel/security/guard.cpp`) blocks a PE or ELF whose
static analysis looks like injection tooling, and the **firewall**
(`kernel/net/firewall.cpp`) drops a packet no rule permits. Both now
offer the same escape hatch — an *exception* — and both keep the same
property that makes the gate worth having: **nothing is allowed unless
someone explicitly said so.**

## The rule that does not bend

An image or packet with no matching exception, on a boot with nobody at
the console, is **denied**. The guard prompt default-denies on timeout;
the firewall drops on its default policy. There is no permissive mode,
no "allow on timeout" switch, and no blanket allow-everything token.
Every widening of the gate is per-item, explicit, and logged.

## Image guard exceptions

### Identity

An exception is keyed on the **SHA-256 digest of the image bytes**, not
its path. `/UNITYPLA.DLL` is a label; the digest is the identity.
Dropping a different file at an excepted path does not inherit the
exception — see [Design-Decisions](../reference/Design-Decisions.md) for
why a path-keyed list is a bypass rather than a convenience, and for the
cost this accepts (an updated binary must be re-approved).

### The three ways in

| Route | Who can use it | When |
|---|---|---|
| Answer `a` at the prompt | anyone at the console/serial | Enforce mode, Warn or Deny verdict |
| `guard except add <sha256>` | `kCapDebug` | any time |
| `guard-allow=<sha256>[,...]` boot token | whoever sets the cmdline | boot, unattended |

The prompt offers three keys, not two:

```
[guard]  Allow once [y] / Always — add exception [a] / Deny [n] — 10s default-deny. >
```

`y` lets this one load through and stores nothing. `a` also records a
persistent exception. They are separate keys on purpose: before this
split, "allow" silently created a standing exception, so an operator who
only wanted to get past one load left a permanent hole behind without
being asked.

### Shell surface

```
guard                         status, incl. exception count and how many were seeded at boot
guard except                  list exceptions (unprivileged — an allowlist is configuration, not a secret)
guard except add <sha256>     add one            (kCapDebug)
guard except del <index>      revoke one         (kCapDebug)
```

### Unattended boots

`guard-allow=` is repeatable and each occurrence takes a comma-separated
list of 64-character hex digests:

```
guard-allow=b47552e3…cf36,e6420b2e…efa8 guard-allow=<another>
```

Every seeded digest is echoed, malformed entries raise a warning (a typo
means an image the operator meant to approve gets denied instead), and a
boot that ran pre-authorised says so:

```
[guard] cmdline exception seeded: sha256=b47552e397a82e2a…
[guard] NOTICE: boot cmdline pre-authorised images — guard exceptions ARE in force
```

The same count appears on the `guard` status line, so an operator who
did not read the boot log still cannot mistake a pre-authorised system
for a clean one.

### Storage and durability

**In-memory (per-boot):** the live list lives in RamVol at
`/run/guard-allowed`, one hex digest per line. This is the
authoritative store for the running system.

**On-disk (cross-reboot):** exceptions are also persisted to `GUARD.DAT`
on the DuetOS-owned FAT32 volume (identified by BPB serial
`kDuetOsVolumeId` + label "DUETOS"; see [Hardware-Safety](Hardware-Safety.md)).
The file format is simple binary: raw 32-byte SHA-256 digests
concatenated, no header. File size is always a multiple of 32.

- **Load:** `GuardLoadDiskExceptions()` runs in `boot_bringup.cpp` after
  FAT32 volumes are probed and mounted. Digests already known from the
  RamVol or cmdline path are not duplicated.
- **Save:** every `GuardRememberAllow` (interactive `a` prompt or shell
  `guard except add`) and `GuardForgetException` rewrites `GUARD.DAT`
  via delete-and-create. `Fat32Sync` flushes the write to stable media.
- **No DuetOS volume:** if no DuetOS-owned volume exists (CI images,
  pre-installer boots), the disk path is a silent no-op and the boot
  cmdline (`guard-allow=`) remains the durable channel.

> **Historical note.** The original store was tmpfs-backed, which capped
> at 512 bytes (seven digest lines), silently dropped everything past
> the seventh, and cut the last survivor mid-digest. RamVol replaced it
> as the in-memory tier; GUARD.DAT now provides cross-reboot durability.

## Firewall exceptions

### Why the shape differs

The guard prompts synchronously because an image load can afford to
block. `FwEvaluate` cannot: it runs on the packet path, so a ten-second
modal per dropped packet would let any port scan stall the network
stack. The firewall therefore asks the question **asynchronously** — a
denial raises a rate-limited toast naming what was blocked and the
command that allows it:

```
firewall blocked in 10.0.2.2:445 — 'firewall except 7' to allow
```

Everything else matches the guard: same three routes in, same cap gate,
same loud logging.

### The three ways in

| Route | Who can use it | Effect |
|---|---|---|
| `firewall except <seq>` | `kCapNetAdmin` | promote a logged denial to a standing allow, `/32`, that exact port |
| `firewall except add <spec>` | `kCapNetAdmin` | install a spec directly (this is how you widen to a subnet) |
| `fw-allow=<spec>[,...]` boot token | whoever sets the cmdline | seed at `FwInit` |

Promoting a denial deliberately produces the *narrowest* rule that
unblocks it — exactly the host that was blocked, exactly that port.
Widening is a separate, deliberate act.

### Spec grammar

```
<in|out> : <any|icmp|tcp|udp> : <A.B.C.D>/<0-32> : <port|*>

in:tcp:10.0.2.2/32:8080     accept inbound TCP to local port 8080 from that host
out:udp:0.0.0.0/0:53        permit outbound DNS to anywhere
in:icmp:192.168.1.0/24:*    accept inbound ping from the LAN
```

The address is the **peer** (source for ingress, destination for
egress); the port is the destination port. Source ports are always
wildcard — they are ephemeral, so pinning one produces an exception that
matches a single connection and never again.

The parser is **fail-closed**: an unrecognised protocol does not fall
back to `any`, a mask above 32 is not clamped, and a malformed spec is
rejected outright rather than partly applied. A half-understood firewall
exception is a hole of unknown shape, which is worse than no exception.
Grammar and rejection cases are pinned in
`tests/host/test_fw_exception.cpp`.

## Verifying it still works

Both mechanisms are self-tested on every boot, and both tests are
**two-sided** — they gate an excepted item and a non-excepted item of
the same verdict on the same boot, because a test that only shows the
allow path cannot tell a working exception apart from a disabled gate.

The guard's proof is one grep-able line:

```
[guard-exception-selftest] PASS (excepted image allowed; non-excepted image still default-denied)
```

Its failure legs fire `kBootSelftestFail` and are picked up by
`tools/test/boot-log-analyze.sh` as a non-deliberate FAIL, so the
self-test doubles as a CI gate. The firewall's equivalent checks live in
`FwSelfTest` and assert that an exception does not generalise to another
peer, port, or protocol.

To confirm the guard test can actually fail, pre-authorise its *control*
fixture and watch it trip:

```
guard-allow=e6420b2efd342cd736b57fe1570f04cf5d9c6ff4dc095fad2261bc5a1ebdefa8
→ [guard-exception-selftest] FAIL: non-excepted image was ALLOWED (gate is not enforcing)
→ boot-log-analyze.sh exits 1
```

## Can a guest reach any of this?

No, and this is the reviewable signal for the slice. Every route in is
either a kernel-side console command behind a capability
(`kCapDebug` for the guard, `kCapNetAdmin` for the firewall), a
physical-presence prompt, or a boot token set before any guest exists. A
PE or ELF has no syscall that adds an exception for itself, so it cannot
do anything a native DuetOS process could not — the property
[Subsystem-Isolation](../kernel/Subsystem-Isolation.md) requires.

## Known limits

- **Cross-reboot persistence requires a DuetOS-owned FAT32 volume.**
  GUARD.DAT is written to the volume identified by `Fat32VolumeIsDuetOsOwned`.
  CI images and pre-installer boots that lack this volume fall back to
  the boot cmdline (`guard-allow=`) as the durable channel.
- **No exception expiry.** An exception lasts until it is revoked or the
  machine reboots. Time-boxed grants exist for capabilities (the
  elevation broker's leases) but are not modelled here.
- **Firewall exceptions are not stored.** They are re-derived each boot
  from `fw-allow=` or re-added by the operator; unlike the guard list
  there is no `/run` file, because a rule table that half-survives a
  reboot is more confusing than one that plainly does not.
- **The blocked packet that raised the toast is lost.** TCP retries and
  the new rule catches the retransmit; a lone UDP datagram is not
  recovered.
