# BusyBox-w32 (`busybox64.exe`)

`busybox64.exe` is the x86_64 native Windows port of BusyBox by Ron
Yorston, downloaded from <https://frippery.org/busybox/> (origin:
<https://github.com/rmyorston/busybox-w32>). License: GPLv2.

Used as the second "really complicated" Windows PE smoke target on
DuetOS, complementary to 7-Zip:

| Property            | 7za.exe     | busybox64.exe   |
| ------------------- | ----------- | --------------- |
| Binary size         | 1.29 MiB    | 717 KiB         |
| Total imports       | 138         | 313             |
| msvcrt imports      | 38          | 147             |
| KERNEL32 imports    | 83          | 118             |
| WS2_32 imports      | 0           | 26              |
| Subsystem           | Console     | Console         |
| Default behavior    | Print help  | Print applet list |

BusyBox is a different beast from 7-Zip: heavy POSIX-style CRT use
(extensive stdio + string + memory + time API surface), built-in
networking utilities (ping/wget/nc → WinSock imports), and 100+
distinct applets that each invoke the full CRT init path.

When invoked with no arguments, busybox prints a short banner +
the list of compiled-in applets — clean exit, no further work.
That's our smoke target.

The kernel embeds this binary verbatim via `duetos_embed_blob` in
`kernel/CMakeLists.txt`; the spawn site is gated behind the
`smoke=pe-busybox` profile.
