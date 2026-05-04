# NASM 2.16.03 — `nasm.exe`

`nasm.exe` is the official x86_64 NASM assembler binary from
<https://www.nasm.us/>, version 2.16.03 (2024-04-17). License:
2-clause BSD (see `LICENSE.txt`).

Used as the third "really complicated" Windows PE smoke target on
DuetOS, complementary to 7-Zip and (the still-blocked) busybox-w32:

| Property            | 7za.exe     | busybox64.exe   | nasm.exe         |
| ------------------- | ----------- | --------------- | ---------------- |
| Binary size         | 1.29 MiB    | 717 KiB         | 1.57 MiB         |
| Total imports       | 138         | 313             | 117              |
| CRT family          | msvcrt      | msvcrt (MinGW)  | UCRT (apisets)   |
| Subsystem           | Console     | Console         | Console          |
| Default behavior    | Print help  | Applet list     | "use --help"     |

NASM is the cleanest of the three from a CRT perspective — it links
against the modern UCRT distributed as the `api-ms-win-crt-*`
apisets (heap / runtime / stdio / string / time / convert /
filesystem / private / environment / utility / math / locale).
Where 7-Zip imports msvcrt.dll directly and busybox-w32 ships its
own MinGW startup, NASM uses the same apiset surface that newer
MSVC builds emit, which we already have first-class thunk support
for.

When invoked with no arguments, NASM prints a one-line usage hint
to stderr and exits cleanly. That's our smoke target.

The kernel embeds this binary verbatim via `duetos_embed_blob` in
`kernel/CMakeLists.txt`; the spawn site is gated behind the
`smoke=pe-nasm` profile.
