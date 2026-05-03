# DuetOS Shell — Scripting v0

The kernel shell ships with a small POSIX-shell-flavoured scripting
language. It's deliberately a subset — no full bash compatibility —
so the parser fits in the kernel and the grammar is something you
can hold in your head. BAT-style `cmd.exe` scripts will live in the
Win32 subsystem when that lands; this page covers the **native**
DuetOS scripting language only.

The interpreter is a small line-indexed walker (`shell_script.cpp`).
Source files passed to `source <path>` (or `.`) run through it; the
same parser also drives one-shot scripted commands.

## Quick reference

```sh
# This is a comment.

# Conditionals.
if cat /etc/version ; then
    echo "version file present"
elif cat /etc/motd ; then
    echo "motd present, version absent"
else
    echo "neither file is present"
fi

# While loop.
set count 0
while expr $count - 3 ; do
    echo $count
    set count $(expr $count + 1)
done

# For loop over a whitespace-split word list.
for name in alice bob carol ; do
    echo "hello, $name"
done

# Exit codes.
true
echo $?       # prints 0
false
echo $?       # prints 1
not-a-command
echo $?       # prints 127
```

## Lexical rules

- One statement per line. `;` is recognised only inside the `if
  CMD ; then` / `while CMD ; do` / `for ... ; do` headers.
- Leading whitespace is ignored.
- Lines starting with `#` are comments. There are no end-of-line
  comments — `echo hi # nope` will pass `# nope` as args to `echo`.
- Empty lines are skipped.
- Lines longer than 63 bytes are truncated, with a klog warning.

## Variables and substitution

- `set NAME VALUE` writes; `unset NAME` removes; `getenv NAME`
  reads. `env` lists every defined slot.
- Whole-token `$NAME` substitution happens before dispatch. Empty /
  undefined vars expand to the empty string.
- `$?` is the exit code of the most recent dispatched command,
  decimal-formatted.
- The env table has 8 slots, 32-byte names, 128-byte values. Beyond
  that, `set` reports "ENV TABLE FULL".

## Control flow

### `if`

```sh
if CMD ; then
    BODY
elif CMD ; then
    BODY
else
    BODY
fi
```

- The condition is any command. The `; then` clause must sit on the
  same line as the `if` / `elif` (split-across-lines is a v1
  feature).
- `$? == 0` → branch is taken.
- `else` and `elif` are optional; you can have an `if .. fi` with
  no else, or chain any number of `elif`s.
- Blocks nest: inner `if ... fi` inside an outer `if ... fi` is
  matched by depth-tracking, so nested blocks don't false-match.

### `while`

```sh
while CMD ; do
    BODY
done
```

- Loops while the condition's `$?` is `0`.
- `^C` aborts cleanly between iterations.
- Capped at 10 000 iterations to prevent runaway loops from wedging
  the shell.

### `for`

```sh
for VAR in WORD1 WORD2 WORD3 ; do
    BODY
done
```

- Iterates over the whitespace-split word list after `in`.
- Each iteration sets `$VAR` via the env table; the previous value
  is overwritten.
- No quoting yet — words are split on every space / tab.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure (file not found, write failed, no match) |
| `2` | Misuse (bad arguments, parse error, divide by zero) |
| `127` | Command not found |

Handlers that haven't been updated yet still default to `0` on every
path. The four classes that scripts will check most often (auth
denial, parse error, file not found, no-match) are wired today —
`true` / `false` / `RequireAdmin` / `expr` / file commands like
`cat` / `head` / `tail` / `wc` / `grep` / `sort` / `uniq` /
`touch` / `rm` / `cp` / `mv`, plus everything in the extended
`shell_extra.cpp` set.

## Built-ins useful in scripts

- `assert <cmd...>` — run CMD; print `ASSERT PASS:` if `$? == 0`,
  else `ASSERT FAIL (exit=N):`. Used as the per-line marker in
  self-test scripts.
- `watch <secs> <cmd...>` — re-run CMD every SECS seconds. Bounded
  at 1000 iterations.
- `script <path> <cmd...>` — run CMD with output captured into a
  tmpfs file. Inner exit code propagates.
- `repeat <N> <cmd...>` — run CMD N times in succession.
- `source <path>` (or `.`) — execute a file as a script. Calls
  through the same interpreter as inline blocks.
- `pause` — block until `^C`. Useful for "give me time to read".
- `sleep <secs>` — wait N seconds.

## Limits (intentional v0)

- **64 lines per script**, **64 bytes per line**. Files bigger than
  that get a `SOURCE: WARNING — script exceeded line cap` and the
  trailing lines are ignored.
- **No functions.** Aliases (`alias name = cmd`) cover the common
  one-line cases; functions land when scripts genuinely need them.
- **No quoting / escaping.** A word with whitespace can't be passed
  as a single argument yet.
- **No here-docs**, no command substitution `$(...)`, no
  arithmetic expansion `$((expr))`. Use `expr` directly and assign
  the result to a variable: `set x $(expr 1 + 2)` will *not* do
  what you want today; use `expr` as the actual command instead.
- **`; then` / `; do` must be on the same line** as the introducer.
  Multi-line `then` / `do` blocks are v1.
- **No backgrounding** (`&`), no job control.

## Worked example: a self-test script

`/tmp/selftest.sh`:

```sh
# DuetOS shell self-test.
echo "== sanity =="
assert true
assert expr 1 + 1
assert expr 0 - 0

echo "== file ops =="
touch /tmp/t.txt
assert ls /tmp/t.txt
echo "hello" > /tmp/t.txt
assert cat /tmp/t.txt
rm /tmp/t.txt

echo "== loops =="
for n in one two three ; do
    echo "  $n"
done

set i 0
while expr $i - 3 ; do
    echo "  iter $i"
    set i $(expr $i + 1)
done

echo "== done =="
```

Run it:

```sh
source /tmp/selftest.sh
```

## Roadmap

Items deferred from v0, in rough priority order:

1. **Quoted strings** so `for x in "with space" ; do ...` works.
2. **Functions** with `name() { body; }` syntax.
3. **Multi-line `then` / `do`** blocks.
4. **Command substitution** `$(...)` and arithmetic `$((...))`.
5. **Larger script buffer** (configurable cap).
6. **`exit N`** to short-circuit a script with a specific code.
7. **`return N`** for the eventual function support.
8. **BAT (`cmd.exe`) interpreter** in the Win32 subsystem.

## Source-of-truth pointers

- Interpreter: `kernel/shell/shell_script.cpp`
- Surface declarations + scope-limit constants: `kernel/shell/shell_internal.h`
- Source command + line buffer: `CmdSource` in `kernel/shell/shell_dispatch.cpp`
- Default profile auto-sourced at boot: `kEtcProfileBytes` in `kernel/fs/ramfs.cpp`
