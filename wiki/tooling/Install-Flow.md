# Installing Third-Party Apps on DuetOS

> **Audience:** anyone who wants to drop a vendored Windows PE
> (game, tool, library) onto DuetOS without rebuilding the kernel.
>
> **Status:** end-to-end pipeline working over HTTP today; HTTPS
> works against any server that accepts `TLS_RSA_WITH_AES_128_GCM_SHA256`
> (most modern CDNs are ECDHE-only and reject — see
> [TLS Roadmap](../networking/TLS-Roadmap.md) Tier 2 for the path).

## The shape of the flow

```
fetch -> verify -> extract -> install -> launch
```

Every step is a plain shell command. No kernel rebuild, no
vendored binary blob.

## Commands

| Step | Command | Notes |
|------|---------|-------|
| Fetch | `wget http://host/foo.zip /downloads/foo.zip` | HTTP works. HTTPS works for RSA-cipher servers. Reports Content-Type / Content-Length, decodes `Transfer-Encoding: chunked`, surfaces `Location:` on 3xx without auto-following. |
| Verify | `sha256sum /downloads/foo.zip` <br> `crc32 /downloads/foo.zip` | Streams via Fat32ReadFileStream — no scratch-cap. SHA-256 is the canonical published hash; CRC-32 is fast sanity. |
| Extract | `unzip /downloads/foo.zip` | Lands at `/unzip/<archive>/...` on FAT32 vol 0. Auto-mkdirs intermediate directories so nested zip entries work. |
| Install | `cp /unzip/foo/foo.dll /lib/foo.dll` <br> (or extract a zip whose entries land directly under `/lib/`) | Any `.dll` under FAT32 `/lib/` is auto-preloaded into every PE process. |
| Launch | `exec /unzip/foo/foo.exe` <br> or Files-app double-click | Files app picks up `.exe` / `.elf` extensions on Enter and routes to `SpawnPeFile` / `SpawnElfFile`. |

## How the DLL pickup works

When `SpawnPeFile` runs, the kernel walks **two** `/lib/`
directories looking for `*.dll` files:

1. **Ramfs `/lib/`** — DLLs baked into the kernel image (the
   curated preload set: `customdll.dll`, `customdll2.dll`,
   plus whatever else ships in the boot ISO). Loaded
   into every PE process by default.
2. **FAT32 vol 0 `/lib/`** — DLLs the user installed at
   runtime. Same auto-preload treatment, but the bytes are
   read off disk into a kernel-side cache so subsequent
   spawns reuse the same buffer.

Both passes run BEFORE `PeLoad` resolves imports, so even
*statically*-imported DLLs in the user-installed .exe pick
up the dropped DLLs via the via-DLL resolver. This is
symmetric with the runtime `LoadLibraryW` path
(`SYS_DLL_LOAD_FROM_PATH`) — install once at any tier,
loader sees it everywhere.

## Limits the user should know about

- **HTTPS reach** — only RSA-cipher servers work. Most modern
  CDNs (GitHub, Cloudflare, Fastly, Google) are ECDHE-only and
  will close the connection at ServerHello. Either find an
  RSA-cipher mirror or wait for the [TLS Tier 2 slice](../networking/TLS-Roadmap.md#tier-2--tls-13--ecdsa--ecdh).
- **No SAN walk yet** — `wget https://...` verifies the leaf
  cert's CN against the URL hostname. A cert that only carries
  the hostname in a Subject Alternative Name extension (the
  modern norm) fails verification. Test with hosts where the
  CN matches.
- **DLL chains** — DuetOS's `DllLoad` does not yet walk the
  loaded DLL's own import table. A DLL with imports of its
  own loads OK but crashes when its first import is called.
  Vendoring large frameworks (Unity, Mono, .NET) is gated on
  this slice landing.
- **No SAN wildcard** — `*.example.com` in the cert's CN does
  not match `foo.example.com`. Exact-match only.
- **FAT32 `/lib/` is volume 0** — the first mounted FAT32
  volume. Adding multi-volume support is a follow-on.
- **Kernel-side DLL cache leaks** — disk-loaded DLL bytes are
  KMalloc'd once and never freed. 16-slot cache, ~64 MiB
  cap per DLL. Acceptable for v0; a real refcount + LRU is
  a follow-on.

## Worked example

```bash
# Verify network reach first.
ping 10.0.2.3              # gateway
nslookup files.example.com # DNS
ifconfig                   # link / IP / gateway / DNS

# Fetch + verify.
wget http://files.example.com/myapp-1.0.zip /downloads/myapp.zip
sha256sum /downloads/myapp.zip   # compare against published hash
crc32 /downloads/myapp.zip

# Extract.
unzip /downloads/myapp.zip
# files now live under /unzip/myapp/...

# Install DLLs into the kernel-visible /lib/.
fatmkdir /lib
cp /unzip/myapp/some.dll /lib/some.dll

# Launch.
exec /unzip/myapp/myapp.exe
# OR open the Files app, navigate to /unzip/myapp/myapp.exe,
# press Enter.
```

## Related pages

- [Live Internet Verification](../networking/Live-Internet.md) —
  proof the network path works against real Internet hosts.
- [TLS Roadmap](../networking/TLS-Roadmap.md) — what HTTPS
  needs to reach Cloudflare et al.
- [PE Loader](../subsystems/PE-Loader.md) — how the v0
  loader maps DLLs into a process AS.
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) —
  what kind of PE actually works.
