# Live security-testing pass — 2026-05-03

Type: Issue + Pattern + Decision
Status: Active
Last updated: 2026-05-03

A live boot-and-attack pass over an OVMF/QEMU-TCG kernel turned up four
distinct kernel-DoS / memory-safety bugs. Each was caught by the
existing in-kernel guard rails (stack canary, attack-sim detector,
PanicAs gate) but only because each guard rail panic'd — i.e. the
guards work, but the bugs are real and shipped today as
unprivileged-process-triggerable kernel crashes.

All four are now fixed and the boot path is clean (no panic, all
attack-sim detectors still PASS for the 8 attacks the 180s-TCG window
reaches before timing out).

## Findings

### 1. Stack-canary corruption / heap buffer overflow in DEFLATE
*kernel/util/deflate.cpp*

`Huffman::symbol[]` was sized `kMaxLitLenSymbols = 286` (RFC 1951's
dynamic-Huffman cap). But `BuildFixed()` writes 288 entries — the
fixed-Huffman code book in §3.2.6 assigns lengths to symbols 0..287
(286/287 are reserved-but-still-encoded). Result: every boot smashed
two `u16` past the array end and the compiler-injected
`__stack_chk_fail` triggered before `DeflateSelfTest` returned.

Fix: introduce `kFixedLitLenSymbols = 288` and size
`Huffman::symbol[]` to it. Dynamic-Huffman validation (`hlit >
kMaxLitLenSymbols`) still rejects oversize tables.

### 2. PBKDF2 boot self-test DoS on QEMU-TCG
*kernel/crypto/pbkdf2.cpp*

RFC 7914 §11 vector 2 runs 80,000 iterations of HMAC-SHA256. On TCG
that takes ~40 seconds and was silently jamming boot before the
attack-sim phase ran. The c=4096 PBKDF2-HMAC-SHA1 vectors already
validate the iteration loop (same logic, different inner hash); the
c=1 SHA256 vector validates the SHA256 inner path. The 80k vector
adds no unique correctness coverage — only stress.

Fix: drop vector 2 with a comment explaining what's still covered.
The boot-time PBKDF2 self-test stays cryptographically meaningful but
is no longer a 40-second wall.

### 3. Unprivileged kernel-DoS via SYS_VM_ALLOCATE / SYS_VM_PROTECT
*kernel/syscall/syscall.cpp*

`AddressSpaceMapUserPage` and `AddressSpaceProtectUserPage` `PanicAs`
on `virt > kUserMax` — a defense against accidental kernel-half user
mappings. Both syscalls accepted a caller-supplied `hint_va` / `base`
without a user-range check, so any process (no caps required for the
self-process path) could pass `0xFFFFFFFF80000000` and PanicAs the
kernel.

Fix: validate `aligned_base + aligned_size <= kUserMax + 1` (with
0-size and overflow rejection) before reaching the AS API. Returns
`kStatusInvalidParameter` instead of panicking.

### 4. Kernel-DoS via malicious PE/DLL ImageBase
*kernel/loader/pe_loader.cpp + kernel/loader/dll_loader.cpp*

`ParseHeaders` read `ImageBase` and `SizeOfImage` from the on-disk PE
without bounds-checking them against `kUserMax`. A crafted PE with
`ImageBase = 0xFFFFFFFF80000000` would reach `MapHeaders ->
AddressSpaceMapUserPage` and trigger PanicAs. Reachable from
`SYS_EXECVE` and every shell `exec` path. The DLL loader had the
identical hole.

Fix: validate `image_base + image_size <= kUserMax + 1` in the
parser, and re-validate post-ASLR-shift in `PeLoad` /
`DllLoad`. Added `PeStatus::ImageBaseOutOfRange` to surface the
rejection in the PE diagnostic line. ELF loader was already correct
(elf_loader.cpp:145).

## Pattern — kUserMax gates panic; syscall surfaces must pre-check

The kernel's `AddressSpaceMapUserPage` /`AddressSpaceProtectUserPage`
panic on out-of-range `virt`. That's the right policy *internally* —
it makes a wrong kernel-side caller a loud bug instead of a silent
data corruption. But it means **any caller path that flows
attacker-controlled VA into those APIs must pre-validate the range
themselves** with a soft-fail (return `kStatusInvalidParameter` /
loader-status) — never reach the panic from a user-driven path.

Audit checklist for new syscalls / loader paths:
1. Identify every user-controlled u64 that's eventually used as a
   user-space VA argument to an `AddressSpace*` API.
2. Confirm a `> kUserMax` rejection happens *before* the API call.
3. Confirm `base + len` overflow is rejected too — both as a
   wraparound (using `(len - 1) > (kUserMax - base)` form) and as a
   crossing of the user/kernel boundary.
4. The check belongs in the syscall handler / loader entry, not in
   the AS API — keep the AS API's panic gate as a "kernel-side
   sanity check" for the trusted-caller contract.

## Resume prompt

> Continuing from
> `.claude/knowledge/security-testing-fixes-2026-05-03.md`. Four
> live-boot security fixes landed: deflate Huffman array overflow,
> PBKDF2 boot self-test DoS, SYS_VM_ALLOCATE/PROTECT user-VA range
> check, PE/DLL ImageBase user-VA range check. Boot is clean
> (no-panic) and attack-sim detectors still PASS. Open follow-ups:
> session self-test FAILED (UI session restore round-trip — not a
> security bug, deferred); attack-sim suite TCG-runtime-bound at 180s
> (only 8 of 11 attacks fit) — separate plan if SMP/KVM lands.
