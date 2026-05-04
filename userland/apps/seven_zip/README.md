# 7-Zip — `7za.exe` (x64)

`7za.exe` is the standalone 7-Zip command-line build (x86_64 PE) from
the official 7-Zip 23.01 release. Used as the "really complicated
Windows PE" smoke target on DuetOS.

Why this binary:

- Console subsystem (Subsystem=3) — no GUI dependency.
- 1.29 MiB binary, 138 imports across 5 DLLs (KERNEL32, msvcrt,
  ADVAPI32, OLEAUT32, USER32) — substantially heavier than the
  ~80 KiB / 12-DLL `windows-kill.exe` that landed before this.
- Self-contained: no external runtime DLLs.
- Pure CRT + Win32; no DirectX, no COM (the OLEAUT32 imports are
  ordinal-only and unused on the help-print path).
- Real-world: Igor Pavlov's mature C++ codebase, exercised by every
  `7z` user on the planet.

Source / license: LGPL + unRAR restriction (see `LICENSE.txt`).
Upstream: <https://www.7-zip.org/>.

The kernel embeds this binary verbatim via
`duetos_embed_blob` in `kernel/CMakeLists.txt`; the spawn site is
gated behind the `smoke=pe-sevenzip` profile.
