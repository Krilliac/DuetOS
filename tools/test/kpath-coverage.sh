#!/usr/bin/env bash
#
# DuetOS code-path coverage diff.
#
# Compares two KERNEL.KPATH.TSV snapshots (or any two TSV files
# produced by the kernel `kpath dump` command) and reports:
#   - newly-visited sites (zero hits in baseline -> nonzero in current)
#   - newly-cold sites    (nonzero in baseline -> zero in current)
#   - per-category visit-count delta
#
# Why bother: the in-RAM ledger surfaces "what ran this boot." Across
# boots, the interesting signals are (a) brand-new code paths that
# fire as you add features and (b) code paths that USED to fire but
# now don't — a silent regression that no PANIC, no test, and no
# klog grep will catch.
#
# Usage:
#   tools/test/kpath-coverage.sh <baseline.tsv> <current.tsv>
#   tools/test/kpath-coverage.sh --baseline <file> --threshold <pct>
#
# Exit status:
#   0  — current is at least as good as baseline (no newly-cold)
#   1  — newly-cold sites detected OR percentage dropped below threshold
#   2  — usage error / missing files / malformed input
#
# Designed to mirror tools/test/boot-log-analyze.sh's interface:
# launcher-agnostic, runs on any TSV captured from any boot, exits
# nonzero on regression so CI can gate on it.

set -u

usage()
{
    cat <<EOF >&2
usage: $0 [--threshold <pct>] <baseline.tsv> <current.tsv>
       $0 --print <current.tsv>

  baseline.tsv  : TSV from a known-good boot
  current.tsv   : TSV from this boot
  --threshold N : fail if current visited% < (baseline visited% - N)
                  default 5 (allow up to 5pp drop before flagging)
  --print       : just print the current TSV in a readable form
EOF
    exit 2
}

threshold=5
print_only=0
baseline=""
current=""
while [ $# -gt 0 ]; do
    case "$1" in
        --threshold)
            shift
            threshold="${1:-5}"
            ;;
        --print)
            print_only=1
            ;;
        --help|-h)
            usage
            ;;
        -*)
            echo "unknown option: $1" >&2
            usage
            ;;
        *)
            if [ -z "$baseline" ]; then
                baseline="$1"
            elif [ -z "$current" ]; then
                current="$1"
            else
                echo "too many positional args" >&2
                usage
            fi
            ;;
    esac
    shift
done

if [ "$print_only" -eq 1 ]; then
    current="$baseline"
    baseline=""
    if [ -z "$current" ]; then
        echo "--print requires a TSV path" >&2
        usage
    fi
fi
if [ -z "$current" ]; then
    usage
fi
if [ ! -f "$current" ]; then
    echo "current TSV not found: $current" >&2
    exit 2
fi
if [ "$print_only" -eq 0 ] && [ ! -f "$baseline" ]; then
    echo "baseline TSV not found: $baseline" >&2
    exit 2
fi

# Filter out comment lines + blank lines; keep only well-formed rows.
strip_tsv()
{
    grep -avE '^(#|$)' "$1"
}

count_visited()
{
    # Column 3 is hits; visited == hits>0.
    strip_tsv "$1" | awk -F'\t' '$3 > 0 {n++} END {print n+0}'
}

count_total()
{
    strip_tsv "$1" | wc -l | tr -d ' '
}

print_summary()
{
    local f="$1"
    local v t pct
    v=$(count_visited "$f")
    t=$(count_total "$f")
    pct=0
    if [ "$t" -gt 0 ]; then
        pct=$((v * 100 / t))
    fi
    echo "  $f : visited=${v}/${t} (${pct}%)"
    # Per-category breakdown.
    strip_tsv "$f" | awk -F'\t' '{cat[$1]+=($3>0?1:0); tot[$1]++}
                                  END {for (c in cat) printf "    %-10s %d/%d\n", c, cat[c], tot[c]}' \
        | sort
}

if [ "$print_only" -eq 1 ]; then
    echo "kpath ledger summary:"
    print_summary "$current"
    exit 0
fi

echo "kpath coverage diff:"
echo "  baseline: $baseline"
echo "  current : $current"
echo
echo "BASELINE summary:"
print_summary "$baseline"
echo
echo "CURRENT summary:"
print_summary "$current"
echo

# Join on (category, name). Build a sortable key per row, then
# diff. Each TSV row has 7 columns; the key is "cat|name", the
# value is hits.
make_keyed()
{
    strip_tsv "$1" | awk -F'\t' '{printf "%s|%s\t%s\n", $1, $2, $3}' | sort
}

bk=$(mktemp)
ck=$(mktemp)
trap 'rm -f "$bk" "$ck"' EXIT
make_keyed "$baseline" > "$bk"
make_keyed "$current" > "$ck"

# Newly-visited: present in both, hits went 0 -> nonzero. OR present
# only in current with hits > 0.
echo "NEWLY VISITED (didn't fire in baseline, fires now):"
join -t$'\t' -a2 -e0 -o 1.2,2.1,2.2 "$bk" "$ck" \
    | awk -F'\t' '$1 == 0 && $3 > 0 {print "  + " $2 "  hits=" $3}'

# Newly cold: present in both, hits went nonzero -> 0. OR present
# only in baseline with hits > 0.
echo
echo "NEWLY COLD (fired in baseline, doesn't fire now):"
newly_cold=$(join -t$'\t' -a1 -e0 -o 1.1,1.2,2.2 "$bk" "$ck" \
    | awk -F'\t' '$2 > 0 && $3 == 0 {print "  - " $1 "  baseline_hits=" $2}')
if [ -n "$newly_cold" ]; then
    echo "$newly_cold"
else
    echo "  (none)"
fi

# Threshold gate.
b_pct=0
c_pct=0
b_v=$(count_visited "$baseline")
b_t=$(count_total "$baseline")
c_v=$(count_visited "$current")
c_t=$(count_total "$current")
[ "$b_t" -gt 0 ] && b_pct=$((b_v * 100 / b_t))
[ "$c_t" -gt 0 ] && c_pct=$((c_v * 100 / c_t))
echo
echo "visited%: baseline=${b_pct}%  current=${c_pct}%  threshold-drop=${threshold}pp"

rc=0
if [ -n "$newly_cold" ]; then
    rc=1
fi
if [ "$c_pct" -lt $((b_pct - threshold)) ]; then
    echo "!! visited% dropped more than ${threshold}pp"
    rc=1
fi
if [ "$rc" -eq 0 ]; then
    echo "verdict: OK"
else
    echo "verdict: REGRESSION"
fi
exit "$rc"
