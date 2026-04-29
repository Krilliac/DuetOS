# Registry static-tree v0 — terminal + prefix tier

**Type:** Decision + Observation
**Status:** Active
**Last updated:** 2026-04-29

## What it is

The kernel's Win32 registry exposes a **two-tier static tree**: a
small set of well-known terminal keys with values, plus the
distinct proper prefixes of those terminal paths as entries with
no values. Both tiers are mirrored in advapi32's user-side tree
(`userland/libs/advapi32/advapi32.c::k_reg_keys[]`) — the
mirror constraint is documented at the top of both files.

```
struct RegKey {
    u64 root;             // predefined HKEY sentinel
    const char* path;     // backslash-separated subkey path
    const RegValue* values;   // nullptr for prefix entries
    u32 value_count;          // 0 for prefix entries
};
```

### Terminals (4 entries, same on kernel + advapi32)

| Root | Path | Values |
|------|------|--------|
| HKLM | `Software\Microsoft\Windows NT\CurrentVersion` | 9 (ProductName, CurrentVersion, …, CurrentMajorVersionNumber) |
| HKLM | `Software\Microsoft\Windows\CurrentVersion` | (alias of above) |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Internet Settings` | 1 (ProxyEnable) |
| HKCU | `Volatile Environment` | 2 (USERNAME, USERDOMAIN) |

### Prefixes (8 entries, same on both sides)

| Root | Path |
|------|------|
| HKLM | `Software` |
| HKLM | `Software\Microsoft` |
| HKLM | `Software\Microsoft\Windows` |
| HKLM | `Software\Microsoft\Windows NT` |
| HKCU | `Software` |
| HKCU | `Software\Microsoft` |
| HKCU | `Software\Microsoft\Windows` |
| HKCU | `Software\Microsoft\Windows\CurrentVersion` |

The HKLM `Software\Microsoft\Windows\CurrentVersion` row is a
TERMINAL (not a prefix) because it carries `kHklmWinNtValues`;
HKCU's same-path row IS a prefix because the only HKCU child
under it is `Internet Settings` and that row owns the values.

## Why two tiers

The first version of the tree had only terminal entries.
Real Win32 PEs frequently OpenKey with a prefix and then narrow:

```c
RegOpenKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft", &h);
RegOpenKeyA(h, "Windows NT\\CurrentVersion", &h2);
```

The first call returned `ObjectNameNotFound` because
`Software\Microsoft` wasn't in the table. Adding prefix rows
(rather than synthesising "virtual prefix" handles in the slot
table) keeps the slot layout unchanged: every handle still points
at a real `RegKey*`, the tier just shows in `value_count == 0`
behaviour at Query/Enumerate time.

## What works

| Operation | Behaviour |
|-----------|-----------|
| `NtOpenKey` / `RegOpenKey*` with a predefined HKEY parent | Walks the static tree at the given path |
| `NtOpenKey` / `RegOpenKey*` with a previously-opened handle as parent | Concatenates `parent.path + "\\" + sub`, looks up the result |
| `NtQueryValueKey` on a terminal | Returns the value (sidecar shadows static at same name) |
| `NtQueryValueKey` on a prefix | Returns `ObjectNameNotFound` (no values) |
| `NtSetValueKey` / `NtDeleteValueKey` | Sidecar pool, cap-gated on `kCapFsWrite` |
| `NtEnumerateValueKey` | Walks `key->values[]` then matching sidecar entries |
| `NtEnumerateKey` | Walks `kRegKeys[]` for direct children of the open key |
| `NtQueryKey` | Reports `subkey_count` (children walker) + `value_count` + `MaxNameLen` + `MaxValueNameLen` + `MaxValueDataLen` |
| `RegEnumKey*` (advapi32) | Same children walker, byte-for-byte mirror in user space |
| `RegEnumValue*` (advapi32) | Walks `key->values[]` |
| `RegQueryInfoKey*` (advapi32) | Same max-len walker as kernel side |

## Wire format — SYS_REGISTRY ops

Op codes are stable ABI (`registry.h::kOp*`):

| Op | Name | rsi (handle) | rdx | r10 | r8 | r9 |
|----|------|-------------|-----|-----|----|----|
| 1 | OpenKey | parent HKEY or kernel handle | path VA | out u64 VA | — | — |
| 2 | Close | handle | — | — | — | — |
| 3 | QueryValue | handle | name VA | buf VA | buf cap | out [type,size] |
| 4 | SetValue | handle | name VA | data VA | size | type |
| 5 | DeleteValue | handle | name VA | — | — | — |
| 6 | FlushKey | — | — | — | — | — |
| 7 | EnumerateValue | handle | index | buf VA | buf cap | — |
| 8 | QueryKey | handle | buf VA (40B) | buf cap | — | — |
| 9 | EnumerateKey | handle | index | buf VA (96B stage) | buf cap | — |

**QueryKey output** (5 u64s, 40 bytes when buf_cap permits, else
truncated to 16 for backwards-compat):

```
[0..8)   subkey_count
[8..16)  value_count
[16..24) max_subkey_name_chars
[24..32) max_value_name_chars
[32..40) max_value_data_bytes
```

ntdll's NtQueryKey thunk maps these onto `KEY_FULL_INFORMATION`
offsets 20 (SubKeys), 24 (MaxNameLen), 32 (Values), 36
(MaxValueNameLen), 40 (MaxValueDataLen).

**EnumerateKey / EnumerateValue staging buffer** (32-byte header
+ name body):

```
[0..4)   index (u32)
[4..8)   reserved
[8..16)  reserved (u64) — used by EnumerateValue for type|size pack
[16..24) reserved or name_chars (depending on op)
[24..32) reserved
[32..)   ASCII name body, NUL-terminated
```

## Mirror discipline

Adding a key to the tree means adding the matching entry in
**both** kernel `registry.cpp::kRegKeys[]` AND advapi32
`k_reg_keys[]` in the same commit. Drift is detectable but not
automated — a future build-time check that compares the two
arrays' shape would close the gap permanently.

## Related landings

- 2026-04-29 — prefix tree + nested OpenKey (commits `a1ec8d9`,
  `f58633b`, `47e844e`, `e0fe826`, `bcc9194`).
- 2026-04-27 — sidecar value pool with `kCapFsWrite` cap-gate
  (commit `0caf60f` + fix `bb6f872`).
- 2026-04-26 — initial registry read syscalls + RegOpenKeyEx
  case-insensitive lookup (commits `e60ce80`, `40a4230`).
