# DuetOS Shell — Command Reference

This page is the single index of every built-in command the kernel
shell understands, generated from the live dispatch table at
`kernel/shell/shell_dispatch.cpp` (see `kCommandSet[]`) and the
companion handler files. Aliases are grouped beside their canonical
form.

The shell is a kernel-resident command prompt — there is no fork/exec,
no `$PATH`, no external binaries. Every command below is a built-in
that calls into a kernel API directly. Commands marked **(admin)**
require an account with the `Admin` role; the gate is enforced inside
the dispatcher (`RequireAdmin`).

## How to invoke

- Type the command, press **Enter**.
- **Up / Down** arrows recall history; **Tab** completes builtin names.
- **Ctrl+C** interrupts long-running commands (the latched flag is
  polled by `seq`, `sort`, `grep`, `sleep`, `pause`, `yes`, …).
- `cmd >  /tmp/out` and `cmd >> /tmp/out` redirect to a tmpfs file.
- `a | b` pipes the captured stdout of `a` as a trailing path arg to
  `b`. Multi-stage pipes recurse.
- `$VAR` substitutes a whole token from the env table.
- `!N` recalls history entry N; `!!` repeats the last command.
- `alias name = expansion` registers a one-level alias (no recursion).

## Quick categories

- [Information & banners](#information--banners)
- [Filesystem (read)](#filesystem-read)
- [Filesystem (write)](#filesystem-write)
- [FAT32 volume tools](#fat32-volume-tools)
- [Environment & shell state](#environment--shell-state)
- [Process & scheduler](#process--scheduler)
- [Hardware introspection](#hardware-introspection)
- [Networking](#networking)
- [Debug & diagnostics](#debug--diagnostics)
- [Security & accounts](#security--accounts)
- [System control](#system-control)
- [Extended get/set/manipulate](#extended-getsetmanipulate)

---

## Information & banners

| Command | Synopsis | Notes |
|---|---|---|
| `help` | List every builtin grouped by category | First stop for discovery |
| `about` | One-line project banner | |
| `version` | DuetOS version string | |
| `uname [-a]` | Kernel identity; `-a` prints arch + tick count | |
| `uptime` | Seconds since the scheduler came online | |
| `date` | Wall time + date from CMOS RTC | `HH:MM:SS YYYY-MM-DD` |
| `cal` | Current month grid via the RTC | |
| `whoami` | Active session user | "(no session)" if logged out |
| `pwd` | Current directory (always `/` in v0) | No per-process cwd yet |
| `hostname` | `$HOSTNAME` or default `duetos` | |
| `windows` | Registered window list + alive flag | |
| `mode` | Current display mode (TTY vs Desktop) | Toggle: Ctrl+Alt+T |
| `theme [LIST\|NEXT\|<name>]` | Show / cycle / set desktop theme | |
| `sysinfo` | One-shot system status summary | |
| `man <name>` | Detailed help for one command | |
| `which <cmd>` | Whether CMD is a builtin or alias | Same data as `type` |
| `time <cmd> ...` | Wall time of a sub-command (10ms) | |

## Filesystem (read)

| Command | Synopsis | Notes |
|---|---|---|
| `ls [path]` | List directory contents | Walks ramfs + tmpfs + /fat |
| `cat <path>` | Print file contents | tmpfs / ramfs / `/fat` |
| `head [-N] <path>` | First N lines (default 5) | |
| `tail [-N] <path>` | Last N lines (default 5) | |
| `wc <path>` | Lines / words / bytes | |
| `grep <pat> <path>` | Lines containing PAT | |
| `find <name>` | Paths whose leaf contains NAME | |
| `sort <path>` | Sort lines alphabetically | |
| `uniq <path>` | Suppress consecutive duplicate lines | |
| `tac <path>` | Print lines in reverse order | |
| `nl <path>` | Number lines | |
| `rev <path>` | Reverse each line's characters | |
| `hexdump <path>` | 16-byte rows of hex + ASCII | |
| `stat <path>` | File / dir metadata | |
| `basename <path>` | Strip leading dirs | Pure string |
| `dirname <path>` | Strip trailing component | Pure string |
| `checksum <path>` | FNV1a-32 hash of file content | |
| `du <path>` | File size in bytes | |

## Filesystem (write)

All write paths target tmpfs (`/tmp/<name>`) unless noted. Ramfs is
read-only at runtime; `/fat/` paths route to the FAT32 driver.

| Command | Synopsis | Notes |
|---|---|---|
| `touch <path>` | Create empty `/tmp` file | |
| `rm <path>` | Remove `/tmp` file | |
| `cp <src> <dst>` | Copy file into `/tmp` | |
| `mv <src> <dst>` | Rename `/tmp` file | |
| `echo ... > path` | Write to `/tmp`; `>>` appends | |
| `truncate <path> <size>` | Resize a `/tmp` file | Zero-fills on grow |
| `mkdir <path>` | Create directory | `/fat` only (admin) |
| `rmdir <path>` | Remove empty directory | `/fat` only (admin) |

## FAT32 volume tools

Volume index defaults to 0 unless an index argument is provided.
All write-side FAT operations are admin-gated.

| Command | Synopsis |
|---|---|
| `fatls [vol]` | List root directory of a FAT32 volume |
| `fatcat [vol] <name>` | Read file from a FAT32 volume to console |
| `fatwrite <path> <off> <bytes>` | Overwrite existing bytes in-place (admin) |
| `fatappend <name> <bytes>` | Append bytes to an existing file (admin) |
| `fatnew <name> [bytes...]` | Create a new file in root, 8.3 name (admin) |
| `fatrm <name>` | Delete a FAT32 file (admin) |
| `fattrunc <name> <size>` | Shrink or zero-grow a file (admin) |
| `fatmkdir <path>` | Create a directory (admin) |
| `fatrmdir <path>` | Remove an empty directory (admin) |
| `read <handle> <lba> [count]` | Hexdump sectors from a block device (admin) |

## Environment & shell state

| Command | Synopsis | Notes |
|---|---|---|
| `set <name> <value>` | Set env variable | `set PS1 '%'` customises prompt |
| `unset <name>` | Remove env variable | |
| `getenv <name>` | Read one env variable | |
| `env` | List env variables | |
| `printenv [name]` | POSIX-flavour env dump (or one value) | |
| `alias [name [cmd...]]` | List / show / set alias | One level expansion |
| `unalias <name>` | Remove alias | |
| `history` | Recent commands; `!N` recalls, `!!` repeats | |
| `clearhist` | Wipe the history ring | |
| `source <path>`, `.` | Run each line of PATH as a command | |
| `repeat <N> <cmd...>` | Run CMD N times (^C aborts) | |
| `pause` | Block until Ctrl+C | |
| `yes [str]` | Print STR up to 100 times (^C aborts) | |
| `sleep <secs>` | Pause N seconds (^C aborts) | |
| `color <fg-hex> [bg-hex]` | Set shell console palette | |
| `reset` | Clear console + reprint MOTD | |
| `clear` | Wipe console only | |

## Process & scheduler

| Command | Synopsis | Notes |
|---|---|---|
| `ps` | List every scheduler task | |
| `top` | Per-task CPU% + system idle fraction | |
| `free` | Memory usage (phys + heap) | |
| `mem` | Physical memory frame totals | |
| `stats` | Scheduler statistics | |
| `loadavg` | Task counts (total / ready) + CPUs | Instantaneous |
| `nproc` | Online CPU count | |
| `yield` | Force a scheduler yield | |
| `kill <pid>` | Terminate a task by ID (admin) | |
| `spawn <kind>` | Launch a ring-3 task: hello / sandbox / jail / … (admin) | |
| `exec <path>` | Dry-run ELF64 load plan (admin) | |
| `readelf <path>` | Parse an ELF64 header + program headers | |
| `linuxexec <path>` | Load ELF as a Linux-ABI process (admin) | |
| `translate` | ABI translation-unit hit table | |

## Hardware introspection

| Command | Synopsis |
|---|---|
| `cpuid [leaf]` | CPU vendor / family / features / brand |
| `cpufeatures` | Decoded CPU feature flags |
| `cr` | Control registers CR0/CR2/CR3/CR4 |
| `rflags` | Current RFLAGS + decoded bits |
| `tsc` | Time-stamp counter (RDTSC) |
| `hpet` | HPET counter + period |
| `ticks` | Timer + scheduler tick counters |
| `msr <hex>` | Read one MSR (admin) |
| `lapic` | Local APIC ID / version / timer |
| `smp` | CPUs online |
| `lspci` | List PCI devices |
| `lsblk` | Registered block devices |
| `lsgpt` | Partitions from GPT-probed disks |
| `lsmod` | Active kernel subsystems |
| `mount` | Filesystem mount table (admin) |
| `df` | Filesystem usage summary |
| `heap` | Kernel heap usage |
| `paging` | Page-table + mapping stats |
| `fb` | Framebuffer geometry |
| `kbdstats` | PS/2 keyboard IRQ counters |
| `mousestats` | PS/2 mouse IRQ counters |
| `smbios` | BIOS / system / chassis info |
| `power`, `battery` | AC / battery / thermal snapshot |
| `thermal`, `temp` | Re-read MSR thermal sensors |
| `hwmon` | Unified sensor view |
| `gpu`, `lsgpu` | List discovered GPUs |
| `gfx` | Graphics-stack overview |
| `vbe [W H [B]]` | Query / set Bochs VBE display mode |
| `monitor [args...]` | Per-display monitor info |
| `port r <port>` | Read one byte from x86 I/O port (admin) |
| `port w <port> <val>` | Write one byte to x86 I/O port (admin) |
| `arch` | Architecture tag (`x86_64`) |

## Networking

| Command | Synopsis | Notes |
|---|---|---|
| `nic`, `lsnic`, `ip` | List NICs + MAC + link | |
| `ifconfig`, `netinfo` | Per-iface link / IP / gateway / DNS / lease | |
| `arp` | ARP cache + stats | |
| `ipv4` | IPv4 RX counters | |
| `dhcp [renew]` | Show lease; renew sends a fresh DISCOVER | |
| `route [-v]` | Default gateway + DNS | `-v` adds gateway ARP |
| `netscan` | Wireless + wired networks reachable | |
| `wifi <args>` | Wi-Fi management subcommands | |
| `ping <ip>` | ICMP echo + 1s reply wait | |
| `nslookup <name>` | DNS A-record lookup | Resolver 10.0.2.3 |
| `ntp [ip]` | NTP query (default 216.239.35.0) | |
| `http <ip> [port [path]]` | TCP connect + GET, prints 16 lines | |
| `net <up\|status\|test>` | Bring up / status / end-to-end smoke | |
| `usbnet [args...]` | USB-network helpers | |
| `fwpolicy [args...]` | Firewall policy view / edit | |
| `fwtrace [show N]` | Firewall trace dispatch points | |
| `crtrace [show N]` | Cleanroom-trace ring dump | |
| `crprobe` | Fire wifi + fw-loader trace dispatch points | |
| `tty` | Console device name (`/dev/console0`) | |

## Debug & diagnostics

| Command | Synopsis | Notes |
|---|---|---|
| `dmesg [TDIWE\|C]` | Dump kernel log ring (or `c` to clear) | |
| `loglevel [L]` | Get / set klog threshold (D/I/W/E) (admin) | |
| `logcolor [args...]` | Toggle klog colour (admin) | |
| `logarea [args...]` | Per-area klog enable (admin) | |
| `kdbg [args...]` | KDBG channel toggles (admin) | |
| `tracer [args...]` | Tracer ring controls | |
| `trace [on\|off]` | Toggle trace threshold + show in-flight scopes | |
| `metrics` | Log resource snapshot | |
| `health`, `checkup` | Runtime invariant scan (heap/frames/sched/CRX) | |
| `dumpstate` | Snapshot every kernel subsystem to serial | |
| `inspect ...` | RE / triage umbrella (syscalls / opcodes / ARM) | |
| `instr <addr> [N]` | Instruction-byte dump at address | |
| `addr2sym <addr>` | Resolve address to symbol | |
| `memdump <addr> [N]` | Hex+ASCII dump of kernel memory (admin) | |
| `bp`, `breakpoint` | Kernel breakpoints (sw + hw) (admin) | |
| `probe <args>` | Runtime probe arming (admin) | |
| `lockdep panic on\|off` | Toggle lock-inversion-promotes-panic (admin) | |
| `cap-audit mode <off\|sample\|full>` | Cap-gate audit verbosity (admin) | |
| `domain <args>` | Restart a fault domain (admin) | |
| `flushtlb`, `flush-tlb` | Reload CR3 (admin) | |
| `perf <args>` | Perf-counter shell front-end | |

## Security & accounts

| Command | Synopsis | Notes |
|---|---|---|
| `users`, `who` | List accounts (`*` = current session) | |
| `useradd <n> <p> [role]` | Create account (admin) | |
| `userdel <n>` | Delete account (admin) | |
| `passwd <old> <new>` | Change own password | |
| `passwd <user> <new> --force` | Admin force-reset | |
| `su <user> <pw>` | Switch session to another user | |
| `login <u> <p>` | Log in non-interactively | |
| `logout` | End session + reopen login gate | |
| `id` | Current user + role | POSIX-flavour |
| `groups` | Active role | |
| `attacksim`, `redteam` | Run red-team attack suite (admin) | |
| `guard [sub]` | Security guard: status / on / enforce / off / test | |
| `secevents`, `events <args>` | Security event ring | |
| `policy <args>` | Security policy view / edit | |
| `purple`, `purpleteam` | Purple-team scenario runner | |

## System control

| Command | Synopsis | Notes |
|---|---|---|
| `reboot` | Reset the machine (admin, no confirm) | |
| `halt` | Stop the CPU (admin, no confirm) | |
| `shutdown`, `poweroff` | ACPI soft-off via `_S5` (admin) | Halts on fallback |
| `beep [hz [ms]]` | PC speaker tone | Default 1000 Hz, 200 ms |
| `sync` | Flush filesystem buffers | No-op in v0 (sync writes) |
| `true` / `false` | No-op success / failure placeholders | |
| `seq <N>` | Print 1..N (cap 200) | ^C aborts |
| `expr <a> <op> <b>` | Integer arithmetic (`+ - * / %`) | |
| `rand [N\|-s\|-hex N]` | Pseudo-random u64s, stats, or raw hex | |
| `uuid`, `uuidgen [N]` | Generate v4 UUIDs from the entropy pool | Cap 20 |

## Extended get/set/manipulate

The "second-tier coreutils" surface added to give the shell a
day-to-day day-to-day feel. Each handler is a thin wrapper around an
existing kernel API.

| Command | Synopsis | Where |
|---|---|---|
| `mkdir <path>` | Create directory (`/fat` only, admin) | `shell_extra.cpp` |
| `rmdir <path>` | Remove empty directory (`/fat` only, admin) | `shell_extra.cpp` |
| `truncate <path> <size>` | Resize a `/tmp` file (zero-fills on grow) | `shell_extra.cpp` |
| `realpath <path>` | Canonicalise path (resolves `.` and `..`, lexical) | `shell_extra.cpp` |
| `id` | Active user + role + admin flag | `shell_extra.cpp` |
| `groups` | Active role only | `shell_extra.cpp` |
| `nproc` | Online CPU count (`SmpCpusOnline`) | `shell_extra.cpp` |
| `arch` | Architecture tag (`x86_64`; ARM64 is a STUB) | `shell_extra.cpp` |
| `tty` | Console device name (`/dev/console0`) | `shell_extra.cpp` |
| `type <cmd>` | Builtin / alias check (mirrors `which`) | `shell_extra.cpp` |
| `printenv [name]` | POSIX env dump or one-value lookup | `shell_extra.cpp` |
| `df` | Filesystem usage (tmpfs / ramfs / blockdevs) | `shell_extra.cpp` |
| `du <path>` | File size in bytes | `shell_extra.cpp` |
| `loadavg` | Total / ready task counts + CPU count | `shell_extra.cpp` |
| `clearhist` | Wipe history ring | `shell_extra.cpp` |
| `pause` | Block until Ctrl+C | `shell_extra.cpp` |
| `yes [str]` | Print STR up to 100 times (^C aborts) | `shell_extra.cpp` |
| `sync` | Flush placeholder (v0 backends are synchronous) | `shell_extra.cpp` |
| `port r <port>` | Read one byte from x86 I/O port (admin) | `shell_extra.cpp` |
| `port w <port> <val>` | Write one byte to x86 I/O port (admin) | `shell_extra.cpp` |
| `assert <cmd...>` | Run CMD; print PASS / FAIL based on `$?` | `shell_extra.cpp` |
| `watch <secs> <cmd...>` | Re-run CMD every SECS seconds (^C aborts, cap 1000) | `shell_extra.cpp` |
| `script /tmp/<name> <cmd...>` | Run CMD with output captured to a tmpfs file | `shell_extra.cpp` |

## Scripting

The shell understands a small POSIX-flavoured scripting language (see
[Shell-Scripting](Shell-Scripting.md) for the full grammar). Quick
summary:

- **Exit codes** — every command sets `$?`. `0` = success, `1` =
  generic failure, `2` = misuse, `127` = command not found. Read it
  back via `$?` in any later argv token.
- **Comments** — lines starting with `#` are skipped.
- **Conditionals** — `if CMD ; then ... [elif CMD ; then ... ]
  [else ... ] fi`. The condition's `$?` decides which branch runs.
- **While loops** — `while CMD ; do ... done`. Loops while the
  condition's `$?` is `0`. Capped at 10 000 iterations.
- **For loops** — `for VAR in W1 W2 W3 ; do ... done`. Iterates the
  whitespace-split word list, writing each value into `$VAR` via the
  env table.
- **Source files** — `source <path>` (or `.`) runs the file as a
  script. Used by `/etc/profile` at shell startup.

Three commands target script authors directly:

- `assert <cmd>` — run CMD and report PASS / FAIL. Used as the
  per-line marker in self-test scripts.
- `watch <secs> <cmd>` — periodic re-run for "tail this output until
  it changes" workflows.
- `script <path> <cmd>` — capture CMD's output to a tmpfs file
  alongside live console output.

---

## Source-of-truth pointers

- Dispatch table & alias mapping: `kernel/shell/shell_dispatch.cpp`
- Per-command handlers split by topic:
  - Trivial: `shell_core.cpp`
  - Filesystem: `shell_filesystem.cpp`
  - Hardware: `shell_hardware.cpp`
  - Network: `shell_network.cpp`
  - Process: `shell_process.cpp`
  - Storage: `shell_storage.cpp`
  - Security / accounts: `shell_security.cpp`
  - Debug / diag: `shell_debug.cpp`
  - Misc utilities: `shell_utilities.cpp`
  - Extended (this page's last section): `shell_extra.cpp`
  - Executable / loader: `shell_exec.cpp`
- Cross-TU surface: `kernel/shell/shell_internal.h`
- Tab-completion + dispatch glue: `kernel/shell/shell.cpp`,
  `shell_complete.cpp`
- History ring + env / alias tables: `kernel/shell/shell_state.cpp`

## Adding a new command

1. Decide which sibling TU it belongs in (or create a new one if the
   existing buckets don't fit).
2. Add the `Cmd<Name>` declaration to `shell_internal.h` under the
   matching section comment.
3. Implement the handler in the chosen TU.
4. Register the canonical name in `kCommandSet[]` in
   `shell_dispatch.cpp` so `which` / `type` / Tab-complete know it.
5. Add an `if (StrEq(cmd, "<name>")) { Cmd<Name>(...); return; }` arm
   to `Dispatch()`. Apply `RequireAdmin("<NAME>")` first if the
   command can hurt the system.
6. Append a one-line summary to the relevant section in `CmdHelp()`
   so it shows in `help`.
7. Update this page (`wiki/reference/Shell-Commands.md`) with a row in
   the right table.
8. Run `clang-format -i` over the touched files; build with
   `cmake --build build/x86_64-release --target duetos-kernel` to
   confirm no warnings.
