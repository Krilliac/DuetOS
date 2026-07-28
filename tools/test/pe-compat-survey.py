#!/usr/bin/env python3
"""
pe-compat-survey.py — rank host Windows binaries by how much of their import
                      surface DuetOS's Win32 subsystem actually implements.

WHAT:
  1. Builds DuetOS's live export surface from BOTH providers a PE can bind to:
       - `userland/libs/<dll>_32/<dll>_32.def` -> i386 companion export lists
       - `userland/libs/<dll>/*.c`             -> `__declspec(dllexport)` (x86_64)
       - `kernel/subsystems/win32/thunks_table.inc` -> the kernel thunk page,
         the x86_64 fallback consulted after the preloaded DLLs' EATs. Omitting
         it under-reports 64-bit coverage badly (it is where GetProcAddress,
         RaiseException and SetStdHandle actually live).
  2. Walks one or more host directories, parses every PE's import directory
     (stdlib only — no pefile dependency), and diffs the imports against the
     surface for that PE's bitness.
  3. Emits JSONL (one record per binary) plus a short ranked stdout summary.

WHY:
  Picking "what to run next on DuetOS" by hand is guesswork: a 40 MB game may
  need three missing exports while a 12 KB console tool needs thirty. This
  turns the choice into a measurement — and re-running it after a slice lands
  shows exactly which binaries the slice unblocked.

  It is also the triage input for the reverse direction: sorting the MISSING
  column by how many candidate binaries want each export gives the highest-
  value implementation order.

USAGE:
  tools/test/pe-compat-survey.py <scan-root> [<scan-root> ...]
      [--repo <path>]      DuetOS checkout to read the surface from (default:
                           two levels up from this script)
      [--out <file.jsonl>] result file (default: pe-compat-survey.jsonl in cwd)
      [--max-bytes N]      skip files larger than N (default 268435456)
      [--top N]            summary rows to print (default 25)
      [--missing-top N]    most-wanted-missing-export rows to print (default 30)
      [--bitness 32|64|any]  restrict the summary to one bitness (default any)

QUICK ANALYSIS (after a run):
  python -c "import json;[print(r['coverage'],r['path']) for r in map(json.loads,open('pe-compat-survey.jsonl')) if r.get('bitness')==32]"
  grep -c '"apiset_count": 0' pe-compat-survey.jsonl
"""

import argparse
import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------
# DuetOS export surface
# --------------------------------------------------------------------------

# `LIBRARY foo.dll` in a .def is authoritative for which DLL the exports
# belong to; the directory name is only a fallback.
_DEF_LIBRARY = re.compile(r"^\s*LIBRARY\s+(\S+)", re.IGNORECASE)
_DEF_EXPORTS = re.compile(r"^\s*EXPORTS\s*$", re.IGNORECASE)
# `__declspec(dllexport) LRESULT CallWindowProcA(` -> CallWindowProcA
_DLLEXPORT = re.compile(r"__declspec\s*\(\s*dllexport\s*\)[^(;]*?(\w+)\s*\(")


def _strip_def_decoration(name):
    """`Foo@16` / `Foo = Bar` / `Foo @3 NONAME` -> `Foo`."""
    name = name.split("=", 1)[0].strip()
    name = name.split()[0] if name.split() else name
    return name.split("@", 1)[0].strip()


def load_surface(repo):
    """Return {dll_lowercase: set(export_names)} for each bitness."""
    libs = os.path.join(repo, "userland", "libs")
    surface = {32: {}, 64: {}}
    if not os.path.isdir(libs):
        sys.exit("error: no userland/libs under %s" % repo)

    for entry in sorted(os.listdir(libs)):
        libdir = os.path.join(libs, entry)
        if not os.path.isdir(libdir):
            continue
        is32 = entry.endswith("_32")
        bits = 32 if is32 else 64
        base = entry[:-3] if is32 else entry
        dll = base.lower() + ".dll"
        names = set()

        for fname in sorted(os.listdir(libdir)):
            path = os.path.join(libdir, fname)
            if fname.endswith(".def"):
                in_exports = False
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.split(";", 1)[0].rstrip()
                        if not line.strip():
                            continue
                        m = _DEF_LIBRARY.match(line)
                        if m:
                            dll = m.group(1).lower()
                            if not dll.endswith(".dll"):
                                dll += ".dll"
                            continue
                        if _DEF_EXPORTS.match(line):
                            in_exports = True
                            continue
                        if in_exports:
                            sym = _strip_def_decoration(line)
                            if sym:
                                names.add(sym)
            elif fname.endswith(".c") or fname.endswith(".h"):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    names.update(_DLLEXPORT.findall(fh.read()))

        if names:
            surface[bits].setdefault(dll, set()).update(names)

    # The api-set contract -> host DLL table the loader binds through.
    apisets = {}
    apiset_src = os.path.join(repo, "kernel", "loader", "apiset_static.cpp")
    if os.path.isfile(apiset_src):
        with open(apiset_src, "r", encoding="utf-8", errors="replace") as fh:
            for head, host in re.findall(r'\{\s*"((?:api|ext)-ms-[^"]+)"\s*,\s*"([^"]+)"', fh.read()):
                apisets[head.lower()] = host.lower()

    # The kernel thunk page — `{"kernel32.dll", "GetProcAddress", kOff...}`.
    # x86_64 only: spawn.cpp does not map the thunk page for PE32 images, which
    # is exactly why the i386 companions had to carry real implementations.
    thunks = os.path.join(repo, "kernel", "subsystems", "win32", "thunks_table.inc")
    if os.path.isfile(thunks):
        with open(thunks, "r", encoding="utf-8", errors="replace") as fh:
            for dll, sym in re.findall(r'\{\s*"([^"]+\.dll)"\s*,\s*"([^"]+)"', fh.read()):
                surface[64].setdefault(dll.lower(), set()).add(sym)

    return surface, apisets


# --------------------------------------------------------------------------
# Minimal PE import parser (stdlib only)
# --------------------------------------------------------------------------


class PeError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


class Pe:
    """Just enough PE to answer 'what does this import'."""

    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("not an MZ image")
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            raise PeError("bad e_lfanew")
        if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise PeError("no PE signature")

        coff = e_lfanew + 4
        self.machine = _u16(data, coff)
        num_sections = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        self.characteristics = _u16(data, coff + 18)

        opt = coff + 20
        if opt_size == 0 or opt + 2 > len(data):
            raise PeError("no optional header")
        magic = _u16(data, opt)
        if magic == 0x10B:
            self.bitness, dd_off = 32, opt + 96
        elif magic == 0x20B:
            self.bitness, dd_off = 64, opt + 112
        else:
            raise PeError("unknown optional-header magic 0x%x" % magic)

        self.subsystem = _u16(data, opt + (68 if self.bitness == 32 else 68))
        self.image_base = (
            _u32(data, opt + 28) if self.bitness == 32 else struct.unpack_from("<Q", data, opt + 24)[0]
        )
        num_dd = _u32(data, opt + (92 if self.bitness == 32 else 108))

        self.dirs = []
        for i in range(min(num_dd, 16)):
            off = dd_off + i * 8
            if off + 8 > len(data):
                break
            self.dirs.append((_u32(data, off), _u32(data, off + 4)))

        self.sections = []
        sec = opt + opt_size
        for i in range(num_sections):
            off = sec + i * 40
            if off + 40 > len(data):
                break
            va = _u32(data, off + 12)
            vsize = _u32(data, off + 8)
            raw_size = _u32(data, off + 16)
            raw_ptr = _u32(data, off + 20)
            self.sections.append((va, max(vsize, raw_size), raw_ptr, raw_size))

    def rva_to_off(self, rva):
        for va, vsize, raw_ptr, raw_size in self.sections:
            if va <= rva < va + vsize:
                delta = rva - va
                if delta >= raw_size:
                    return None  # lives in the zero-fill tail; nothing on disk
                return raw_ptr + delta
        return None

    def _cstr(self, off):
        if off is None or off < 0 or off >= len(self.data):
            return None
        end = self.data.find(b"\0", off)
        if end < 0:
            return None
        return self.data[off:end].decode("ascii", "replace")

    def _walk_thunks(self, thunk_rva):
        """Yield imported-by-name symbols from one thunk array."""
        step = 4 if self.bitness == 32 else 8
        ord_flag = 0x80000000 if self.bitness == 32 else 0x8000000000000000
        off = self.rva_to_off(thunk_rva)
        if off is None:
            return
        for i in range(4096):  # generous cap; guards a corrupt/looping table
            pos = off + i * step
            if pos + step > len(self.data):
                return
            val = _u32(self.data, pos) if step == 4 else struct.unpack_from("<Q", self.data, pos)[0]
            if val == 0:
                return
            if val & ord_flag:
                yield "#%d" % (val & 0xFFFF)
                continue
            name_off = self.rva_to_off(val + 2)  # skip the Hint word
            name = self._cstr(name_off)
            if name:
                yield name

    def imports(self):
        """Return {dll_lowercase: [symbol, ...]} across normal + delay imports."""
        out = {}

        def add(dll, syms):
            if not dll:
                return
            out.setdefault(dll.lower(), set()).update(syms)

        # Directory 1 — the import table.
        if len(self.dirs) > 1 and self.dirs[1][0]:
            off = self.rva_to_off(self.dirs[1][0])
            if off is not None:
                for i in range(2048):
                    pos = off + i * 20
                    if pos + 20 > len(self.data):
                        break
                    oft, _ts, _fc, name_rva, first = (_u32(self.data, pos + k) for k in (0, 4, 8, 12, 16))
                    if not (oft or name_rva or first):
                        break
                    dll = self._cstr(self.rva_to_off(name_rva))
                    add(dll, self._walk_thunks(oft or first))

        # Directory 13 — delay imports. Games load d3d/xinput this way, so
        # ignoring it would under-report the surface a title actually needs.
        if len(self.dirs) > 13 and self.dirs[13][0]:
            off = self.rva_to_off(self.dirs[13][0])
            if off is not None:
                for i in range(1024):
                    pos = off + i * 32
                    if pos + 32 > len(self.data):
                        break
                    attrs = _u32(self.data, pos)
                    name_rva = _u32(self.data, pos + 4)
                    int_rva = _u32(self.data, pos + 16)
                    if not (name_rva or int_rva):
                        break
                    # attrs bit0 clear => the RVAs are really VAs (old linkers).
                    if not (attrs & 1):
                        name_rva -= self.image_base
                        int_rva -= self.image_base
                    dll = self._cstr(self.rva_to_off(name_rva))
                    add(dll, self._walk_thunks(int_rva))

        return {k: sorted(v) for k, v in out.items()}


# --------------------------------------------------------------------------
# Survey
# --------------------------------------------------------------------------

# api-ms-win-* / ext-ms-win-* are apiset forwarders. DuetOS has no apiset
# resolver, so a binary importing them is blocked before any export matters.
_APISET = re.compile(r"^(api-ms-win-|ext-ms-win-)", re.IGNORECASE)


def _apiset_head(dll):
    """`api-ms-win-core-synch-l1-2-0.dll` -> `api-ms-win-core-synch-l1`.

    Mirrors ApiSetResolveStatic: strip `.dll`, then the trailing
    `-<major>-<minor>` version pair, leaving the head the table keys on.
    """
    name = dll.lower()
    if name.endswith(".dll"):
        name = name[:-4]
    parts = name.split("-")
    while len(parts) > 1 and parts[-1].isdigit():
        parts.pop()
    return "-".join(parts)


def classify(pe, surface, apiset_map):
    imports = pe.imports()
    known = surface.get(pe.bitness, {})
    # The loader's last-resort api-set fallback is "first preloaded
    # export by name wins" (TryResolveViaPreloadedDllsAnyName), so a
    # contract import resolves if ANY preloaded DLL exports the name.
    # Modelling only the host lookup under-reports badly: hello_md.exe
    # scored 42% and then ran to a clean exit.
    any_name = set()
    for names in known.values():
        any_name |= names

    resolved, missing, apisets, unknown_dlls = [], [], [], []
    for dll, syms in sorted(imports.items()):
        if _APISET.match(dll):
            apisets.append(dll)
            host = apiset_map.get(_apiset_head(dll))
            have = known.get(host, set()) if host else set()
            for s in syms:
                # Host EAT first, then the any-preloaded-name fallback —
                # the same two steps, in the same order, as the binder.
                (resolved if (s in have or s in any_name) else missing).append("%s!%s" % (dll, s))
            continue
        have = known.get(dll)
        if have is None:
            unknown_dlls.append(dll)
            missing.extend("%s!%s" % (dll, s) for s in syms)
            continue
        for s in syms:
            (resolved if s in have else missing).append("%s!%s" % (dll, s))

    total = len(resolved) + len(missing)
    return {
        "bitness": pe.bitness,
        "subsystem": pe.subsystem,
        "image_base": pe.image_base,
        "dll_count": len(imports),
        "import_count": total,
        "resolved_count": len(resolved),
        "missing_count": len(missing),
        "coverage": round(len(resolved) / total, 4) if total else 1.0,
        "apiset_count": len(apisets),
        "apisets": apisets,
        "unknown_dlls": unknown_dlls,
        "missing": missing,
    }


def iter_pes(roots, max_bytes):
    seen = set()
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fn in filenames:
                if not fn.lower().endswith((".exe", ".dll", ".com")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(path) > max_bytes:
                        continue
                except OSError:
                    continue
                real = os.path.normcase(os.path.abspath(path))
                if real in seen:
                    continue
                seen.add(real)
                yield path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument("--out", default="pe-compat-survey.jsonl")
    ap.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--missing-top", type=int, default=30)
    ap.add_argument("--bitness", choices=("32", "64", "any"), default="any")
    args = ap.parse_args()

    surface, apiset_map = load_surface(args.repo)
    sys.stderr.write(
        "surface: %d x86_64 DLLs (%d exports), %d i386 DLLs (%d exports)\n"
        % (
            len(surface[64]),
            sum(len(v) for v in surface[64].values()),
            len(surface[32]),
            sum(len(v) for v in surface[32].values()),
        )
    )

    rows, want = [], {}
    scanned = skipped = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for path in iter_pes(args.roots, args.max_bytes):
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                pe = Pe(data)
                rec = classify(pe, surface, apiset_map)
            except (PeError, OSError, struct.error, IndexError):
                skipped += 1
                continue
            rec["path"] = path
            rec["size"] = len(data)
            rec["exe"] = path.lower().endswith(".exe")
            rows.append(rec)
            out.write(json.dumps(rec) + "\n")
            scanned += 1
            if rec["bitness"] == 32 and rec["exe"]:
                for m in rec["missing"]:
                    want[m] = want.get(m, 0) + 1

    sys.stderr.write("scanned %d PEs (%d unparseable)\n" % (scanned, skipped))

    cand = [r for r in rows if r["exe"] and r["import_count"] > 0]
    if args.bitness != "any":
        cand = [r for r in cand if r["bitness"] == int(args.bitness)]
    # Rank by coverage, then by how few holes are left — a 100%-covered binary
    # with 40 imports is a better next rung than one with 3.
    cand.sort(key=lambda r: (-r["coverage"], r["missing_count"], -r["import_count"]))

    print("\n== most-runnable host .exe candidates ==")
    print("%-6s %-5s %-6s %-6s %-7s  %s" % ("cover", "bits", "imps", "miss", "apiset", "path"))
    for r in cand[: args.top]:
        print(
            "%-6.1f%% %-5d %-6d %-6d %-7d  %s"
            % (r["coverage"] * 100, r["bitness"], r["import_count"], r["missing_count"], r["apiset_count"], r["path"])
        )

    print("\n== most-wanted missing exports (32-bit .exe demand) ==")
    for name, n in sorted(want.items(), key=lambda kv: -kv[1])[: args.missing_top]:
        print("%4d  %s" % (n, name))

    print("\nwrote %s" % os.path.abspath(args.out))


if __name__ == "__main__":
    main()
