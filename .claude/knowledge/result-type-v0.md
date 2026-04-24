# Result<T, E> — kernel exception-handling primitive (v0)

**Last updated:** 2026-04-23
**Type:** Decision + Pattern
**Status:** Active — primitive landed, one call site converted, migration is opportunistic

## What

`kernel/core/result.h` — a `std::expected`-shaped `Result<T, E = ErrorCode>`
type that's the canonical way every fallible operation returns its
error to its caller. C++ exceptions are off globally
(`-fno-exceptions`); CLAUDE.md mandates a `Result<T, E>` type and
this file is that type.

## Shape

```cpp
namespace duetos::core {

enum class ErrorCode : u32 {
    Ok = 0, OutOfMemory, InvalidArgument, NotFound, AlreadyExists,
    PermissionDenied, Timeout, Unsupported, BadState, IoError,
    Truncated, BufferTooSmall, Overflow, Corrupt, NotReady, Busy,
    NoDevice, Unknown,
};

template<typename E> struct Err { E value; };        // CTAD-friendly

template<typename T, typename E = ErrorCode>
class Result {
  bool has_value();
  const T& value();
  E error();
  T take();
};

template<typename E>
class Result<void, E> {                              // status-only
  bool has_value();
  E error();
};

} // namespace

// Early-return at the call site:
#define RESULT_TRY(expr)                 // Result<void> / discard value
#define RESULT_TRY_ASSIGN(decl, expr)    // bind T to `decl`
```

`T` and `E` must be trivially copyable (freestanding kernel — no
`<new>`, no destructors in Result storage). That covers every
"simple return" shape we care about in kernel code today:
pointers, ints, POD structs like `MsixRoute`, `PhysAddr`.

## Canonical usage

```cpp
::duetos::core::Result<Thing> MakeThing() {
    if (bad)
        return ::duetos::core::Err{ErrorCode::InvalidArgument};
    return Thing{...};
}

Result<void> UseIt() {
    RESULT_TRY_ASSIGN(Thing t, MakeThing());
    RESULT_TRY(SomeVoidThing(t));
    return {};  // ok
}
```

The `Err{code}` helper uses CTAD so the enclosing function's
return type doesn't have to be spelled out in the error path.

## Why not std::expected

The freestanding kernel link doesn't pull in `<expected>` /
`<variant>` / `<optional>`. `std::expected` also has a
non-trivial destructor (union of T + E, both potentially
non-trivial), which would force placement-new machinery. This
v0 type is 8..48 bytes depending on T, trivially copyable,
zero-overhead vs a raw `{bool, T}`.

If we ever host C++ userland with exceptions enabled, that code
is free to use `std::expected`; the kernel stays on this type.

## Migration policy

- **New code**: default to `Result<T>` for any fallible operation
  where the caller might reasonably want to differentiate between
  failure modes. Single-error-mode predicates (`bool IsReady()`)
  stay as `bool`.
- **Existing code**: migrate opportunistically when touching a
  surface for another reason. Don't do blanket conversion PRs —
  they swamp review and delete useful context.
- **Panic boundaries**: hard-invariant checks (KASSERT) stay.
  `Result<T>` is for conditions the caller can legitimately
  observe and recover from — not for "kernel state corruption"
  (which should panic + crash-dump).

## First converted surface

`drivers::pci::PciMsixRouteSimple` — flipped from
`bool f(..., MsixRoute* out)` to `Result<MsixRoute> f(...)`. Call
sites become:

```cpp
RESULT_TRY_ASSIGN(pci::MsixRoute r,
                  pci::PciMsixRouteSimple(addr, 0, lapic, vec));
```

No legacy callers existed (helper landed in `a5ec7f3` and is
brand new) so there's zero migration cost. Subsequent drivers
that wire MSI-X routing get the Result-shaped API from day one.

## Boot-time self-test

`ResultSelfTest()` runs early in `kernel_main`:
- Result<u64> success + error paths
- Result<void> success + error
- TRY macro chain (success propagation + failure short-circuit)
- ErrorCodeName coverage for every enum value

Panics on mismatch; prints `[result-selftest] PASS` on success.

## Next candidates for conversion

Picked to demonstrate the pattern on real kernel surfaces:
- `mm::MapMmio` — currently returns `void*` with nullptr on
  failure. Convert to `Result<void*>` with `OutOfMemory` /
  `InvalidArgument`.
- `fs::ext4::Ext4Probe` — currently returns `bool` + out-param.
  Convert to `Result<Volume>`.
- `drivers::storage::BlockDeviceRead` — currently returns `i32`
  Linux-style (-1 on error). Convert to `Result<void>` with
  specific codes.

None of these are load-bearing blockers; they move the codebase
toward a uniform error-propagation surface one slice at a time.

## References

- `kernel/core/result.h` — the primitive.
- `kernel/core/result.cpp` — `ErrorCodeName` + self-test.
- `kernel/drivers/pci/pci.{h,cpp}::PciMsixRouteSimple` — first
  converted call site.
