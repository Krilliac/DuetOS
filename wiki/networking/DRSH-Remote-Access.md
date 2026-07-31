# DRSH — DuetOS Remote SHell + Desktop

> **Audience:** Net stack hackers, operators enabling remote access
>
> **Execution context:** Kernel — server accept loop + per-session
> channel loop run in process context on a worker thread
>
> **Maturity:** active — encrypted PSK-authenticated shell + desktop
> over TCP; single channel per session, no public-key auth (see v0 limits)

DRSH is DuetOS's native equivalent of SSH: a single authenticated,
encrypted carrier that multiplexes an interactive terminal channel and
a remote-desktop (framebuffer + input) channel. It is **not**
bit-compatible with SSH-2 — the kernel does not (yet) have the big-int
crypto that public-key auth needs.

| Property | Value |
|---|---|
| Default TCP port | 4322 |
| Symmetric cipher | AES-128-CTR |
| Frame integrity | HMAC-SHA256, 16-byte tag |
| Password KDF | PBKDF2-HMAC-SHA256, 4096 iters |
| Auth | Mutual challenge-response over a pre-shared password |
| Channels per session | 1 (shell **or** desktop), v0 |
| Concurrent sessions | 1 authenticated DRSH session at a time. TCP v1 can host independent 5-tuples, but DRSH still has one global session record and one synchronous worker. |

Source: [`kernel/net/drsh/`](../../kernel/net/drsh/). Shell command:
`drshd`.

## Quick start

The service is **off** by default. An admin enables it explicitly:

```text
$ drshd passwd hunter2
DRSHD: password updated
$ drshd start
DRSHD: listener started
$ drshd status
DRSH: listener=running, password=set, port=4322
DRSH: session=idle, authenticated=no
DRSH: connections=0, auth_failures=0, frames rx/tx=0/0
```

Stop the listener with `drshd stop`; rotate the password with
`drshd passwd <newpass>` (only while the listener is stopped).

## Live DRSH agent campaign

The host-side agent campaign is a separate test surface from
`tools/security/drsh_attack.py` and `tools/security/drsh_os_attack.py`. It
boots a throwaway QEMU guest with the test-only `DUETOS_DRSH_AUTOSTART=ON`
build option, forwards DRSH to a loopback-only host port, and starts
independent `drsh_agent.py` processes. Each process performs a real DRSH
handshake, opens the shell channel, runs its command plan inside the guest,
and closes the session.

From the WSL-native checkout, with a build that already has the option enabled:

```text
python3 tools/security/drsh_host.py --agent recon --agent second-recon --jsonl
```

The kernel build must run in a WSL-native checkout. From PowerShell, sync the
Windows source into a bounded WSL scratch tree, then run the campaign there:

```text
wsl.exe -d Ubuntu-24.04 -- bash -lc "DUETOS_SRC=/mnt/c/Users/<you>/DuetOS bash /mnt/c/Users/<you>/DuetOS/tools/build/sync-to-wsl-scratch.sh /root/scratch/duetos-drsh-agent-host"
wsl.exe -d Ubuntu-24.04 -- bash -lc "cd /root/scratch/duetos-drsh-agent-host && python3 tools/security/drsh_host.py --build --preset x86_64-debug --jsonl"
```

Running `--build` from PowerShell is rejected deliberately: CMake caches and
kernel objects created through `/mnt/c` and `C:/` are different path domains.

The default plan is two non-destructive agents (`recon` and `operator`). The
built-in `control` profile writes one marker under `/tmp`, reads it back, and
checks a capability-denied operation; select it only with the explicit guest
control acknowledgement:

```text
python tools/security/drsh_host.py --agent controller:control --agent observer:recon --i-understand-guest-control
```

For other custom commands, provide a JSON array and explicitly acknowledge that
commands can mutate, stop, or expose data from the guest:

```json
[
  {"name": "recon", "profile": "recon"},
  {"name": "controlled-operator", "commands": ["id", "drshd status", "policy show"]}
]
```

```text
python3 tools/security/drsh_host.py --plan agent-plan.json --i-understand-guest-control
```

Agents are intentionally scheduled one at a time because DRSH v0 owns one
global authenticated session and one synchronous worker. The campaign keeps
the guest endpoint on `127.0.0.1`, writes guest and per-agent logs to a
temporary campaign directory, and stops QEMU when complete. Use
`--keep-guest` plus `--connect-only --host-port <port>` for a follow-up
campaign against the same locally running guest.

## Threat model

DRSH defends against an attacker on the wire — passive eavesdropping
and active tampering — but **trusts the local host**. The pre-shared
key lives in kernel state (`g_global.password`) and is rotated by the
admin. A compromised admin shell trivially defeats this; that's
outside the model and consistent with the way SSH treats `/etc/shadow`.

Specifically, DRSH provides:

- **Confidentiality** of every byte after `AUTH_OK` (AES-CTR keystream
  derived from PMK + both-side nonces).
- **Per-frame integrity** (HMAC-SHA256-128 over the cleartext header
  and the ciphertext; encrypt-then-MAC; constant-time tag compare).
- **Replay protection** in two ways: each direction's AES-CTR counter
  is monotone within a session, so an earlier frame replayed mid-
  session fails the MAC; cross-session replays fail because the
  session keys themselves are derived from fresh nonces.
- **No password exfil**: the password never crosses the wire, only an
  HMAC-SHA256 response under a PBKDF2-derived PMK salted with the
  server's per-session nonce.
- **Brute-force lockout**: after `kDrshLockoutThreshold` (5) consecutive
  handshakes that complete the AUTH step with a wrong password, the
  listener refuses **all** new connections — without running any crypto —
  for `kDrshLockoutDurationNs` (60 s), auto-thawing on expiry. This
  mirrors the console-login lockout in `security/auth.cpp`, so a remote
  attacker faces the same wall the local login already puts up. Only
  genuine wrong-password handshakes feed the streak: malformed frames,
  version mismatches, and bare TCP connects that drop before AUTH do
  **not** count, so a port scanner can't lock the admin out (self-DoS).
  A successful handshake, a `drshd passwd` rotation, or `drshd unlock`
  clears the streak; `drshd status` shows `lockout=`, `failed_streak`,
  and `throttled` (connections refused while locked).

DRSH does **not** provide:

- **Public-key auth**. No RSA / DH / curve25519 in the kernel yet.
- **Forward secrecy** between successive sessions sharing a password.
  Compromising the password retroactively decrypts captured traffic
  because PMK is a deterministic function of `(password, nonce_s)`. A
  follow-up ECDHE handshake variant will land once an in-tree
  big-int + curve subsystem exists.
- **Concurrent authenticated sessions.** The kernel's TCP v1 stack
  can host independent 5-tuples (see [`TCP State Machine`](TCP-State-Machine.md)),
  and DRSH now accepts real on-wire TCP children, but the service still
  owns one global `DrshSession` record and runs one synchronous channel
  loop on the listener worker. Additional clients must wait for the current
  session to tear down or be refused by the listener/backlog.

## Threading & Locking Model

- The **accept loop** (`drsh_server.cpp`) runs in process context on a
  worker thread, polling `SocketAcceptNonblocking` so `drshd stop` can
  be observed between accept probes. Each accepted on-wire connection rides
  its own TCB on its own 5-tuple, but the DRSH worker services only one
  accepted session at a time.
- Each session's **channel loop** runs synchronously on the same worker:
  it drives the handshake, then services exactly one channel (shell or
  desktop) before tearing down — there is no per-channel task, which is
  why v0 caps a session at one channel.
- All socket I/O blocks in process context; nothing in DRSH runs from an
  IRQ handler. Session state (keys, counters, the pre-shared password in
  `g_global.password`) lives in kernel globals mutated only on this
  worker path.

## Wire protocol

### Frame format

```
+---+---+-------+-----------------+----------+
| t | c | length (BE u16) | payload (CT) | MAC (16) |
+---+---+-------+-----------------+----------+
```

| Field | Bytes | Description |
|---|---|---|
| `type` | 1 | Frame type (see below) |
| `channel` | 1 | 0 = control, 1 = shell, 2 = desktop |
| `length` | 2 BE | Payload length, 0..4096 |
| `payload` | `length` | AES-CTR ciphertext (cleartext pre-auth) |
| `MAC` | 16 | HMAC-SHA256(mac_key, type ‖ channel ‖ length ‖ payload)[:16] |

Pre-handshake frames (HELLO, CHALLENGE, AUTH, AUTH_FAIL) carry a
zero MAC — the keys to compute one don't exist yet. Their contents
are bound into the session keys via the KDF, so a man-in-the-middle
who tampers with them produces a session in which the two sides
derive different keys; the very first authenticated frame (AUTH_OK)
fails the receiver's MAC check.

### Frame types

| Value | Name | Direction |
|---|---|---|
| 1 | `kDrshFrameHelloC` | C → S |
| 2 | `kDrshFrameHelloS` | S → C |
| 3 | `kDrshFrameChallenge` | S → C |
| 4 | `kDrshFrameAuth` | C → S |
| 5 | `kDrshFrameAuthOk` | S → C |
| 6 | `kDrshFrameAuthFail` | S → C |
| 10 | `kDrshFrameChannelOpen` | C → S |
| 11 | `kDrshFrameChannelOpenAck` | S → C |
| 12 | `kDrshFrameChannelDenied` | S → C |
| 13 | `kDrshFrameChannelData` | both |
| 14 | `kDrshFrameChannelClose` | both |
| 20 | `kDrshFrameDisconnect` | both |
| 30 | `kDrshFramePing` | both |
| 31 | `kDrshFramePong` | both |

### Handshake

```
C -> S : HELLO_C       { magic(4 BE) | version(2 BE) | nonce_c[16] }
S -> C : HELLO_S       { magic(4 BE) | version(2 BE) | nonce_s[16] }
S -> C : CHALLENGE     { challenge[32] }
C -> S : AUTH          { hmac_response[32] }

  hmac_response = HMAC-SHA256(pmk,
                              "DRSH-AUTH" || nonce_s || nonce_c || challenge)
  pmk           = PBKDF2-HMAC-SHA256(password,
                                     "DRSH-PMK" || nonce_s,
                                     4096, 32)

S verifies (constant-time compare). On success it derives:

  session_enc_key  = HMAC-SHA256(pmk, "DRSH-ENC" || nonce_s || nonce_c)[:16]
  session_mac_key  = HMAC-SHA256(pmk, "DRSH-MAC" || nonce_s || nonce_c)[:32]
  session_ctr_s2c  = HMAC-SHA256(pmk, "DRSH-IVS" || nonce_s || nonce_c)[:16]
  session_ctr_c2s  = HMAC-SHA256(pmk, "DRSH-IVC" || nonce_s || nonce_c)[:16]

S -> C : AUTH_OK       (first MAC'd frame in the session)
```

### Channels

Once authenticated:

```
C -> S : CHANNEL_OPEN  { kind(1) }   kind = 0 (shell) | 1 (desktop)
S -> C : CHANNEL_OPEN_ACK { channel_id(1) }
                                  channel_id = 1 (shell) | 2 (desktop)
... ChannelData frames flow until either side sends ChannelClose.
```

Only one channel is open per session in v0 (the server runs the
channel's service loop synchronously). Open a fresh session for the
other kind.

#### Shell channel (`channel_id = 1`)

Inbound `CHANNEL_DATA` is treated as one UTF-8 command line per frame
(trailing CRLF stripped). The server runs the line through the kernel
shell's `Dispatch()` and tees the resulting console writes back as
one `CHANNEL_DATA` frame, then sends a `"drsh$ "` prompt. The line
`exit` / `quit` triggers a graceful `CHANNEL_CLOSE`.

#### Desktop channel (`channel_id = 2`)

Inbound `CHANNEL_DATA` carries input events; outbound `CHANNEL_DATA`
carries framebuffer tile updates. The payload's first byte is a
sub-type:

| Sub-type | Direction | Payload (after sub-type byte) |
|---|---|---|
| 0 `TileBlit` | S → C | `x_be(2) y_be(2) w_be(2) h_be(2)` + `w*h*4` BGRA bytes |
| 1 `FrameStart` | S → C | `width_be(2) height_be(2) bpp flags(2)` |
| 2 `FrameEnd` | S → C | (empty) |
| 3 `InputKey` | C → S | `code_le(2) modifiers press(1)` |
| 4 `InputMouse` | C → S | `dx_be(i16) dy_be(i16) buttons` |
| 5 `ResizeAck` | C → S | reserved; ignored in v0 |

Tile geometry is 32 × 30 pixels max per frame (chosen so
`32 * 30 * 4 + 9` ≤ `kDrshMaxPayload`); tail rows / columns of the
framebuffer come back as smaller tiles. The server sends a full
frame, then drains one `Recv` of input before sending the next
frame — input is responsive, redraws are batched.

## v0 limits

These are intentional, documented limits. Each one points at a
future slice that lifts it.

- **Single authenticated DRSH session.** TCP v1 lifted the old single-slot
  wire limit, and DRSH can now accept real TCP children, but per-session
  task/state allocation is still needed before multiple authenticated
  clients can run concurrently.
- **Pre-shared key only.** No public-key auth. Lifted by adding
  ECDHE on top of an in-tree curve25519 implementation.
- **Single channel per session.** The service runs the channel
  loop synchronously. Lifted by adding per-channel kernel tasks
  with channel-multiplexing.
- **No damage tracking on desktop channel.** Every redraw sends
  the full framebuffer. Lifted by reading the framebuffer driver's
  `g_damage` union and only emitting tiles that intersect it.
- **32-bit BGRA framebuffer only.** Other depths refuse the
  channel cleanly. Lifted when the framebuffer driver gains
  configurable-depth support.

## Self-test

`DrshSelfTest()` runs at boot, derives session keys from a known
PMK + nonces, encrypt-then-MACs a 13-byte message through an
in-memory transport, verifies the decrypt + MAC-check returns the original
plaintext, and covers the brute-force lockout state machine. Emits one
explicit `PASS` line so CI can grep for it:

```
[net/drsh-selftest] PASS (frame round-trip + lockout)
```

## Reading the source

- [`kernel/net/drsh/drsh.h`](../../kernel/net/drsh/drsh.h) — public surface, protocol constants.
- [`kernel/net/drsh/drsh_internal.h`](../../kernel/net/drsh/drsh_internal.h) — internal types, transport vtable.
- [`kernel/net/drsh/drsh_crypto.cpp`](../../kernel/net/drsh/drsh_crypto.cpp) — AES-CTR, HMAC, frame send/recv.
- [`kernel/net/drsh/drsh_auth.cpp`](../../kernel/net/drsh/drsh_auth.cpp) — handshake, PMK derivation, session keys.
- [`kernel/net/drsh/drsh_transport.cpp`](../../kernel/net/drsh/drsh_transport.cpp) — socket-backed transport wrapper.
- [`kernel/net/drsh/drsh_shell.cpp`](../../kernel/net/drsh/drsh_shell.cpp) — shell channel service.
- [`kernel/net/drsh/drsh_desktop.cpp`](../../kernel/net/drsh/drsh_desktop.cpp) — desktop channel service.
- [`kernel/net/drsh/drsh_server.cpp`](../../kernel/net/drsh/drsh_server.cpp) — accept loop, session orchestration, self-test.
- [`kernel/shell/shell_drsh.cpp`](../../kernel/shell/shell_drsh.cpp) — `drshd` shell command.
