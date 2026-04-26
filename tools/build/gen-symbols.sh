#!/usr/bin/env bash
#
# Generate the kernel's embedded symbol table.
#
# Reads function symbols (name + addr + size) from a stage-1 kernel
# ELF, resolves each one to a source file + line number via
# addr2line, and emits a C++ translation unit that the stage-2
# kernel links in as `symbols_generated.cpp`.
#
# Output format — compact but parseable:
#
#     namespace duetos::core {
#         extern "C" const SymbolEntry g_duetos_symtab_entries[] = {
#             { 0xffff..., size, line, "name", "path/file.cpp" },
#             ...
#         };
#         extern "C" const u64 g_duetos_symtab_count = N;
#     }
#
# Usage:
#     tools/build/gen-symbols.sh <stage1.elf> <out.cpp> <repo_root>
#
# The repo_root argument is stripped from absolute source paths so
# the embedded file strings are relative (e.g. `kernel/core/panic.cpp`).
#
# Requires: llvm-nm (or nm), llvm-addr2line (or addr2line),
#           c++filt (only if the ELF was produced without C++ demangling
#           already baked into nm output).

set -euo pipefail

if (( $# != 3 )); then
    echo "usage: $0 <stage1.elf> <out.cpp> <repo_root>" >&2
    exit 2
fi

readonly STAGE1_ELF="$1"
readonly OUT_CPP="$2"
readonly REPO_ROOT="$3"

if [[ ! -f "${STAGE1_ELF}" ]]; then
    echo "gen-symbols: stage-1 ELF not found: ${STAGE1_ELF}" >&2
    exit 1
fi

# Pick the best available tools. Prefer llvm-* — their output is
# inlining-aware, and they demangle identically to what c++filt does.
if command -v llvm-nm >/dev/null 2>&1; then
    NM="llvm-nm"
    NM_ARGS=(--print-size --demangle --defined-only --numeric-sort)
elif command -v nm >/dev/null 2>&1; then
    NM="nm"
    NM_ARGS=(-S -C --defined-only -n)
else
    echo "gen-symbols: need llvm-nm or nm on PATH" >&2
    exit 1
fi

if command -v llvm-addr2line >/dev/null 2>&1; then
    ADDR2LINE="llvm-addr2line"
elif command -v addr2line >/dev/null 2>&1; then
    ADDR2LINE="addr2line"
else
    echo "gen-symbols: need llvm-addr2line or addr2line on PATH" >&2
    exit 1
fi

# Scratch files — cleaned up on exit regardless of outcome.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

readonly SYMS_RAW="${WORK}/syms.raw"
readonly SYMS_FILTERED="${WORK}/syms.filtered"
readonly ADDR_LIST="${WORK}/addrs.list"
readonly LINES_RAW="${WORK}/lines.raw"

# ----------------------------------------------------------------------------
# 1. Pull all function symbols with non-zero addresses.
#    `nm -S` format:  "<addr> <size> <type> <name>"    (four fields)
#                or:  "<addr> <type> <name>"           (three fields; no size)
#    We want type chars T (global text) or t (local text).
# ----------------------------------------------------------------------------
"${NM}" "${NM_ARGS[@]}" "${STAGE1_ELF}" > "${SYMS_RAW}"

# Keep only text symbols with addresses above the higher-half base —
# the low-half `.text.boot` trampoline is identity-mapped and can also
# be resolved, but its addresses overlap nothing interesting post-boot
# and aren't useful for crash dumps. Filter aggressively: the dump
# path cares about the running kernel's code, which is all in the
# higher half (VA >= 0xFFFF800000000000).
#
# We use string comparison (not numeric) because `mawk`, the default on
# Ubuntu, doesn't implement `strtonum`. nm outputs zero-padded 16-char
# lowercase hex, so "higher half" <=> "starts with ffff8 or higher".
awk '
    function is_higher_half(hex) {
        # Zero-padded 16 char lowercase hex string. Higher-half VAs
        # are 0xFFFF8000_00000000 and above, i.e. the leading 5 hex
        # chars compare >= "ffff8".
        if (length(hex) != 16) { return 0; }
        return (substr(hex, 1, 5) >= "ffff8");
    }
    function tail_from(nstart,   i, out) {
        out = $nstart;
        for (i = nstart + 1; i <= NF; ++i) { out = out " " $i; }
        return out;
    }
    # nm line with size present:  "addr size type name..."   (name may contain spaces)
    # nm line without size:       "addr type name..."
    NF >= 4 && ($3 == "T" || $3 == "t") {
        if (is_higher_half(tolower($1))) { printf "%s %s %s\n", $1, $2, tail_from(4); }
        next;
    }
    NF >= 3 && ($2 == "T" || $2 == "t") {
        if (is_higher_half(tolower($1))) { printf "%s 0 %s\n",   $1, tail_from(3); }
        next;
    }
' "${SYMS_RAW}" > "${SYMS_FILTERED}"

# Drop exact-duplicate addresses — the kernel sometimes has an alias
# symbol (e.g. ".text.startup" entry + C++ name) at the same VA. Keep
# the first occurrence; numeric-sort + awk seen-map handles it.
awk '!seen[$1]++' "${SYMS_FILTERED}" > "${SYMS_FILTERED}.dedup"
mv "${SYMS_FILTERED}.dedup" "${SYMS_FILTERED}"

# ----------------------------------------------------------------------------
# 2. Resolve each entry address to a source file:line with addr2line.
#    One invocation per symbol would be O(N) forks — batch into a
#    single stdin-fed call instead, which is O(1) forks.
# ----------------------------------------------------------------------------
awk '{ print "0x" $1 }' "${SYMS_FILTERED}" > "${ADDR_LIST}"
"${ADDR2LINE}" -e "${STAGE1_ELF}" < "${ADDR_LIST}" > "${LINES_RAW}"

# ----------------------------------------------------------------------------
# 3. Emit the generated C++ TU. Strings are stored inline per entry —
#    the linker will fold identical string literals across rows via
#    `-fmerge-constants` (on by default at -O1+), so the rodata cost
#    is roughly one copy per unique file + one per unique demangled
#    name. If it becomes a real problem later, swap to a pooled-string
#    offset format; the resolver API is stable enough for that.
# ----------------------------------------------------------------------------
{
    printf '// Auto-generated by tools/build/gen-symbols.sh — do not edit.\n'
    printf '//\n'
    printf '// Source: %s\n' "$(basename "${STAGE1_ELF}")"
    printf '// Function symbols: sorted by virtual address (ascending).\n'
    printf '\n'
    printf '#include "util/symbols.h"\n'
    printf '\n'
    printf 'namespace duetos::core {\n'
    printf '\n'
    printf 'extern "C" const SymbolEntry g_duetos_symtab_entries[] = {\n'
} > "${OUT_CPP}"

# Walk both files in lockstep. `paste -d\|` merges them on a sentinel
# separator so we can awk a single stream.
paste -d'|' "${SYMS_FILTERED}" "${LINES_RAW}" | awk -v repo="${REPO_ROOT}" '
    function cstring_escape(s,   out, i, c) {
        out = "";
        for (i = 1; i <= length(s); ++i) {
            c = substr(s, i, 1);
            if (c == "\\") out = out "\\\\";
            else if (c == "\"") out = out "\\\"";
            else if (c == "\t") out = out "\\t";
            else if (c == "\r") out = out "\\r";
            else if (c == "\n") out = out "\\n";
            else                 out = out c;
        }
        return out;
    }
    {
        # Left side: "addr size name..."   (name may have spaces)
        # Right side: "file:line" or "??:0" or "??:?"
        split($0, parts, "|");
        left  = parts[1];
        right = parts[2];

        # Left: split on the first two space runs. The tail is the
        # (possibly-spaced) demangled name.
        si1 = index(left, " ");
        if (si1 == 0) { next; }
        addr = substr(left, 1, si1 - 1);
        rest = substr(left, si1 + 1);
        sub(/^ +/, "", rest);
        si2 = index(rest, " ");
        if (si2 == 0) { next; }
        size = substr(rest, 1, si2 - 1);
        name = substr(rest, si2 + 1);
        sub(/^ +/, "", name);

        # Right: trim trailing whitespace, split on last colon.
        sub(/[[:space:]]+$/, "", right);
        cidx = 0;
        for (i = length(right); i > 0; --i) {
            if (substr(right, i, 1) == ":") { cidx = i; break; }
        }
        if (cidx == 0) { file = right; line = "0"; }
        else            { file = substr(right, 1, cidx - 1); line = substr(right, cidx + 1); }
        if (line == "?" || line == "") { line = "0"; }

        # Strip repo root prefix so the stored path is relative.
        if (substr(file, 1, length(repo) + 1) == repo "/") {
            file = substr(file, length(repo) + 2);
        }
        if (file == "" || file == "?") { file = "??"; }

        # Sanitize for C string literals.
        name_esc = cstring_escape(name);
        file_esc = cstring_escape(file);

        printf "    { 0x%sULL, 0x%su, %su, \"%s\", \"%s\" },\n",
               addr, size, line, name_esc, file_esc;
    }
' >> "${OUT_CPP}"

# Trailing entries + count.
entry_count="$(wc -l < "${SYMS_FILTERED}" | tr -d ' ')"
{
    printf '};\n'
    printf '\n'
    printf 'extern "C" const duetos::u64 g_duetos_symtab_count = %su;\n' "${entry_count}"
    printf '\n'
    printf '} // namespace duetos::core\n'
} >> "${OUT_CPP}"

echo "gen-symbols: ${entry_count} entries -> ${OUT_CPP}"
