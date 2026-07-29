# TPM 2.0 — the sealing half, and only the sealing half

DuetOS talks to a TPM 2.0 over the FIFO/TIS interface. It implements
sealing, PCR measurement and the hardware RNG. It does not implement,
and will not implement, endorsement-key export, attestation identity
keys, or quote signing.

That is a deliberate product decision, not a gap in the driver. This
page records what was built, how the refusal is enforced, and the one
condition under which the rule would be reopened.

## The rule

> **DuetOS implements the SEALING half of TPM and never the IDENTITY
> half.**

| In scope | Out of scope, permanently |
|---|---|
| Seal / unseal of local secrets, bound to a PCR policy | Endorsement key (EK) export, EK certificate reads |
| PCR extend + read | Attestation identity keys (AIKs) |
| Hardware RNG | `TPM2_Quote` and every other signed assertion |
| Non-exportable key storage, monotonic counters | Any remote attestation protocol |

The out-of-scope column is not an arbitrary line. Those commands, and
only those commands, turn a TPM into a stable, remote-visible hardware
identity. They are the mechanism behind device fingerprinting and
"only approved configurations get service" lock-out. Everything in the
left column is useful to the machine's owner and useless to a remote
party trying to identify them.

A TPM is a passive coprocessor with no network path of its own. It
cannot leak anything the OS does not choose to send. So the defence is
not to filter what the chip says — it is to never build the sender.

### The condition that would void the rule

Nothing about a hardware generation, a vendor, a certification
programme, or a piece of software that "requires attestation to run"
is sufficient. The rule would be reopened only if DuetOS itself grew a
use for a signed assertion that never leaves the machine **and** the
project could demonstrate that the same signed structure could not be
replayed to a remote verifier. Absent a proof of that second half the
answer is no — "an application wants it" is precisely the demand the
rule exists to refuse.

## How the refusal is enforced

By capability and by construction, not by a policy check that a future
edit could quietly invert. Four independent layers:

1. **There is no raw passthrough.** `kernel/drivers/tpm/tpm.h` exposes
   typed operations (`TpmGetRandom`, `TpmPcrRead`, `TpmPcrExtend`)
   that build their own commands. There is deliberately no
   "submit these bytes to the TPM" entrypoint, because one would let
   any caller hand-marshal `TPM2_Quote` and walk around every other
   layer. This is the most important of the four.
2. **The transport holds an allow-list.** `wire::CommandAllowed()` in
   `kernel/drivers/tpm/tpm_wire.h` enumerates the sealing-half opcodes;
   `TpmTisTransact` refuses anything else before a byte reaches the
   FIFO. It is an allow-list, so an opcode nobody has considered yet is
   refused by default.
3. **The refused opcodes are named.** `kCcQuote`, `kCcCertify`,
   `kCcActivateCredential`, `kCcGetTime` and the rest are written down
   as constants next to the allow-list, so a reader who greps for them
   finds an explicit refusal rather than an absence they might read as
   an oversight — and so that adding one to the allow-list is a visible
   diff under the comment explaining why it must not be.
4. **Tests fail if someone adds attestation.**
   `tests/host/test_tpm_wire.cpp` asserts each identity-half opcode is
   refused, and the boot self-test re-asserts it on every machine,
   with or without a TPM.

There is no ring-3 syscall in this slice: no guest binary can reach the
TPM at all, by any path. When a guest-facing seal API lands it will be
cap-gated and its key material derived per-application and salted per
install, so two applications cannot correlate on a shared identifier
even locally.

## What is implemented

| Piece | State | Notes |
|---|---|---|
| TIS/FIFO transport | REAL | Locality handshake, burst-count flow control, `tpmGo`, response read |
| Presence detection | REAL | Distinguishes absent, present-but-unstartable, and working |
| ACPI TPM2 table | REAL | Read for the Start Method only; FIFO (2, 6) accepted, CRB (7/8/11) and ACPI-Start (1) refused |
| `TPM2_Startup` | REAL | Handles the already-started-by-firmware case |
| `TPM2_GetRandom` | REAL | Mixed into the kernel entropy pool at boot |
| `TPM2_PCR_Read` | REAL | One PCR per call, SHA-256 bank |
| `TPM2_PCR_Extend` | REAL | Password auth area |
| Measured-boot tripwire | REAL | See below |
| Seal / unseal | MISSING | Command codes are on the allow-list; the marshalling for `CreatePrimary` / `Create` / `Load` / `Unseal` and the policy-session handling are not written yet |
| CRB interface | MISSING | `// GAP:` in `tpm.cpp`; revisit when a target machine reports it |

Registers are at the architectural window `0xFED40000`. That covers a
discrete LPC/SPI chip and an fTPM in AMD PSP or Intel PTT identically —
from the OS side they are the same register file, which is why there is
one driver and not three.

### Absence is never faked

A machine with no TPM reads all-ones from the unbacked window and
reports `present=no (no TIS responder at 0xFED40000)`. A chip that
answers the bus but fails `TPM2_Startup` reports `present=no` with a
*different* reason. Those are distinct observable states and the boot
log distinguishes them. No path substitutes a zero, an empty digest, or
a fabricated success for hardware that is not there.

## Measured boot as a local tripwire

`kernel/drivers/tpm/tpm_measure.cpp` answers one question, on this
machine, for this machine's owner: **has the boot chain changed since I
last looked?**

Detection without reporting. Nothing signs a PCR set and nothing sends
one anywhere. The composite digest is a function of the firmware and the
kernel configuration, not of the chip's endorsement key — two machines
with identical firmware and an identical boot command line produce an
identical digest, so it could not single out a machine even if it did
leak. That property is load-bearing, not incidental.

A mismatch **warns**; it does not refuse to boot. Refusing to boot on a
PCR mismatch is exactly the lock-out behaviour this design set out to
avoid. The tripwire's job is to tell the owner, not to decide for them.

What is measured:

| PCR | Contents |
|---|---|
| 0-7 | Firmware's own measurements (not ours) |
| 8, 9 | GRUB's — **excluded from the composite**, see below |
| 10 | Kernel build identity (git hash + branch) |
| 11 | Kernel command line, minus the `tpm.baseline=` token |

The composite is SHA-256 over PCR 0-7, 10 and 11, each **read back from
the chip** rather than computed locally — that is what makes anything
else that extended a PCR visible.

Two exclusions are deliberate and were both found by running the thing:

- **PCR 8 and 9 are GRUB's.** Its TPM module measures its own commands
  into 8 and the files it loads into 9, and those commands include the
  raw kernel command line — the pinned baseline included. Folding them
  in made the digest depend on the baseline, so pinning it changed it
  and no boot could report a match. Observed directly: two boots
  differing only in the baseline value produced different digests.
- **The `tpm.baseline=` token is stripped before PCR 11.** Same
  self-reference, one level up.

### Arming it

Boot once, read the digest from the `[tpm-measure]` line, and pin it:

```
tpm.baseline=<64 hex characters>
```

`// GAP:` this only holds where editing the boot configuration leaves
the boot **image** byte-identical, because PCR 4 measures that image.
A conventional install, whose boot config is a file the loader reads,
is fine. Under `tools/qemu/run.sh`, `DUETOS_EXTRA_CMDLINE` rebuilds the
ISO with the config embedded in the EFI image, so PCR 4 moves with the
baseline and no pinned boot in that harness can report `match`.

The deeper limitation is that the baseline shares storage with the thing
it measures, so someone who can edit the boot configuration can add a
token *and* re-pin. The fix is a baseline that lives outside the
measured set — a persistent store, ideally with the baseline sealed to
the TPM. DuetOS has no writable persistent store yet (see
[Persistence](Persistence.md)); when it lands, it becomes an additional
baseline source rather than a redesign.

## Testing it

QEMU emulates a TPM, so this is testable on a dev box without hardware:

```bash
sudo apt-get install -y swtpm swtpm-tools
DUETOS_TPM=1 tools/qemu/run.sh
```

`run.sh` starts a per-run `swtpm` and attaches it as `-device tpm-tis`.
It fails loudly if `swtpm` is missing rather than booting without a TPM,
because a silent fallback would make an absent-TPM run masquerade as a
TPM run and turn the self-test into a false green.

Expected on a good boot:

```
[tpm] present=yes
[tpm-tis-selftest] PASS
[tpm-selftest] PASS (live: rng + pcr read)
[tpm-measure] boot-integrity=unpinned digest=<64 hex>
```

Hosted tests: `tpm_wire` (marshalling and the allow-list) and `cmdline`
(token parsing and the strict hex decoder the baseline depends on).

## Notes for the next person

Two things cost real time during bring-up and are worth knowing:

- **`TPM_STS` bits are not packed upward from bit 0.** `stsValid` is
  bit 7 and `commandReady` bit 6 (TCG PC Client PTP §6.5.2.5). The
  intuitive guess yields a driver that reads a perfectly plausible
  status byte and then waits forever on a bit that means something
  else. A self-test now pins the whole layout.
- **ACPI Start Method 6 is FIFO, not CRB.** 6 is the TPM 2.0
  FIFO-over-MMIO interface and is what QEMU's `tpm-tis` reports; only
  7, 8 and 11 are the Command Response Buffer. Refusing 6 makes the
  driver stand down on hardware it can actually drive.

The per-PCR values are logged at DEBUG during the composite fold, so an
unexpected `CHANGED` can be narrowed to a single PCR in one boot rather
than by bisection.
