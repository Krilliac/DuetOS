# Rust bring-up plan — when, where, how

**Last updated:** 2026-04-21
**Type:** Decision
**Status:** Active (pre-bring-up — no Rust in tree yet)

## Description

DuetOS is C++23 / ASM today. CLAUDE.md permits Rust for
**greenfield subsystems where memory-safety vs. C++ lifetime
invariants matter** — explicitly called out: filesystem drivers,
USB stack, network stack. This entry locks in WHEN that first
Rust subsystem lands, WHERE in the tree it lives, and HOW the
toolchain + build + kernel linkage come online so the bring-up
is boring when it happens.

## Context

Applies to:

- Any future PR that proposes introducing Rust.
- Toolchain / build-system changes that would anticipate Rust
  (premature — don't land them).
- CI additions (a Rust job belongs next to `build-debug` /
  `build-release` once a Rust subsystem actually exists).

Does **not** apply to:

- Kernel C++ code. Kernel stays C++23 forever for hot paths
  (scheduler, paging, syscall dispatch) — Rust doesn't buy
  lifetime safety for a monolithic shared-state kernel.
- Win32 / NT subsystem. PE/COFF loader, NT syscall layer,
  kernel32/ntdll/user32/... are C++23 by design (they exist to
  run Windows binaries; an ABI-compatible reimplementation
  benefits nothing from Rust's ownership model).

## Details

### When — triggers for the first Rust subsystem

Any ONE of these justifies starting a Rust subsystem. If none
apply, stay on C++.

1. **Real on-disk filesystem** — our native FS, NTFS read path,
   ext4 read path. Trigger when a slice actually starts parsing
   on-disk metadata from an attacker-controllable byte stream
   (superblocks, directory entries, extent trees). Canonical
   Rust ROI case: hostile byte stream + pointer-heavy parse.

2. **USB class drivers with descriptor parsing** — xHCI host
   controller is fine in C++ (MMIO / TRB ring state machine,
   mostly small-integer bit-bashing). The USB *class* drivers
   (HID, MSC, hub) parse device-supplied descriptor chains,
   which is the real memory-safety surface.

3. **TCP/IP stack** — packet headers from untrusted peers. Skip
   Rust for the link-layer drivers (e1000 / iwlwifi — mostly MMIO
   + DMA ring) but start Rust at the protocol stack boundary.

4. **Anything else with non-trivial parsing of attacker-supplied
   structured bytes** — image formats, compression, font files,
   crypto framings. Lower priority; surfaces on demand.

**Not** a trigger:

- "Memory safety is cool" — we take the compile cost + build
  complexity seriously. The C++23 slice has to have a real
  lifetime problem, not an aesthetic one.
- "A library exists in Rust" — porting one subsystem to Rust so
  we can use a single crate is a rewrite tax for a dependency.
  Either rewrite the library in C++ or skip the feature.
- "Other OSes use Rust here" — true of many drivers; we still
  make the call per subsystem.

### Where — tree layout

First Rust subsystem example, assuming it's our native FS:

```
fs/customfs/                  (NEW — Rust crate)
├── Cargo.toml                (no_std, panic-abort)
├── build.rs                  (emit static lib, link to kernel)
├── src/
│   ├── lib.rs                (entry: pub extern "C" fn customfs_*)
│   ├── super_block.rs
│   ├── inode.rs
│   └── dir.rs
└── include/
    └── customfs.h            (C header, hand-written — DO NOT use bindgen)

rust-toolchain.toml           (NEW — pin nightly)
```

**Rules:**

- **One crate per subsystem.** Never a shared "rust-utils" crate
  until a second subsystem actually needs the shared bits. No
  premature factoring.
- **No Rust in the middle of a C++ call chain.** The kernel C++
  side calls Rust through a narrow C FFI; Rust calls back into
  C++ only through a matching narrow C FFI; both surfaces are
  auditable in a single header. Never C++ → Rust → C++ → Rust.
- **No `unsafe` in subsystem code except at the FFI wall.** The
  FFI wall is allowed `unsafe` (has to be — that's where raw
  pointers enter), but internal subsystem code that uses
  `unsafe` needs a 1-line comment explaining *which kernel
  invariant justifies it*.
- **Header is hand-written, not bindgen.** Bindgen pulls in
  cbindgen-style automation noise and makes the C/Rust contract
  implicit. A hand-written `.h` keeps the wall obvious and
  reviewable.

### How — toolchain

Pin in `rust-toolchain.toml` at the repo root:

```toml
[toolchain]
channel = "nightly-YYYY-MM-DD"     # pin date when bring-up lands
components = ["rust-src", "rustfmt"]
targets = ["x86_64-unknown-none"]
```

**Why nightly:** `-Zbuild-std` (needed for `no_std` against
a bare-metal target without a pre-built `core` / `alloc`).
`x86_64-unknown-none` is stable; the `-Zbuild-std` flag is
not.

**Why pin a date:** the nightly surface can churn
week-over-week. A pinned date means `cargo build` is
reproducible. Bump the pin in a dedicated PR, never in a
subsystem PR.

### How — crate config

Every subsystem crate:

```toml
[package]
name = "customfs"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[profile.release]
panic = "abort"
lto = "thin"
opt-level = 3
codegen-units = 1         # deterministic symbol layout

[profile.dev]
panic = "abort"
opt-level = 1             # kernel code is too slow unoptimised
debug = true
```

**Why `panic = "abort"`:** the kernel can't unwind. Unwinding
requires landing pads, `libunwind`, and a C++ runtime — none
of which exist in this kernel. An `abort` panic compiles to a
`ud2` / halt call that the kernel's #UD handler routes to
`panic()`. Same policy Linux uses for Rust-for-Linux.

**Why `lto = "thin"`, not `"fat"`:** fat LTO interacts badly
with CMake + multiple object files on our kernel link. Thin
LTO keeps per-crate inlining + ships a single `.a`.

### How — build system

CMake side (`fs/customfs/CMakeLists.txt`):

```cmake
# Invoke cargo to produce libcustomfs.a, then wrap it as a
# CMake INTERFACE target the main kernel link consumes.
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/libcustomfs.a
    COMMAND cargo build --release
            --target x86_64-unknown-none
            -Z build-std=core,alloc
            --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
            --target-dir ${CMAKE_CURRENT_BINARY_DIR}/target
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_BINARY_DIR}/target/x86_64-unknown-none/release/libcustomfs.a
            ${CMAKE_CURRENT_BINARY_DIR}/libcustomfs.a
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/lib.rs ...
    VERBATIM)
add_custom_target(customfs-rust DEPENDS libcustomfs.a)
add_library(customfs STATIC IMPORTED GLOBAL)
set_target_properties(customfs PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libcustomfs.a)
add_dependencies(customfs customfs-rust)
target_include_directories(customfs INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
```

Kernel CMakeLists gains `target_link_libraries(duetos-kernel
PRIVATE customfs)`. The `.a` links into the kernel ELF
alongside the C++ object files; `lld` resolves the C FFI
symbols.

### How — kernel integration

The C FFI header exposes kernel functions Rust can call (frame
alloc, page mapping, logging) and Rust functions the kernel
calls:

```c
// fs/customfs/include/customfs.h  (hand-written)

// Kernel functions the Rust side calls.
extern void  duetos_klog_info (const char* tag, const char* msg);
extern void* duetos_kmalloc   (unsigned long n);
extern void  duetos_kfree     (void* p);

// Rust functions the kernel calls.
extern int   customfs_mount  (const void* blob, unsigned long len);
extern long  customfs_read   (unsigned long ino, unsigned long off,
                              void* buf, unsigned long cap);
```

Rust side in `src/lib.rs`:

```rust
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

extern "C" {
    fn duetos_klog_info(tag: *const u8, msg: *const u8);
}

#[panic_handler]
fn on_panic(_info: &PanicInfo) -> ! {
    // SAFETY: string literals are C-compatible NUL-terminated.
    unsafe { duetos_klog_info(b"customfs\0".as_ptr(),
                                b"rust panic\0".as_ptr()); }
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn customfs_mount(blob: *const u8, len: usize) -> i32 {
    // ... parse superblock ...
    0
}
```

### How — CI

When the first Rust subsystem lands, the GitHub Actions
workflow grows one job alongside `build-debug`:

```yaml
build-rust:
  name: build rust subsystems
  runs-on: ubuntu-24.04
  steps:
    - uses: actions/checkout@v4
    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@master
      with:
        toolchain: nightly-YYYY-MM-DD
        components: rust-src, rustfmt
        targets: x86_64-unknown-none
    - name: Format check
      run: cargo fmt --all --manifest-path fs/customfs/Cargo.toml -- --check
    - name: Build
      run: |
        cd fs/customfs
        cargo build --release \
          --target x86_64-unknown-none \
          -Z build-std=core,alloc
```

The main `build-debug` / `build-release` jobs implicitly depend
on this because CMake invokes `cargo` as part of the kernel
build. Keep the Rust job too so compile failures surface with a
clearer error than "cmake couldn't find libcustomfs.a".

## Notes

- **Do not** install a Rust toolchain on the dev host
  speculatively. The dev host should install Rust with the
  same one-liner CLAUDE.md uses for QEMU: "install when a
  task legitimately requires it."
- **Do not** introduce a Rust util crate (common types,
  panic handler, etc.) until two subsystems actually share
  something — two occurrences is the rule.
- **Do not** use Rust for a kernel driver that's mostly MMIO
  bit-bashing with no parsing surface. xHCI's TRB rings are
  a fine example of "no Rust ROI here."
- **Do not** adopt a Rust build system (Bazel, Nix, Meson)
  even if it models Rust better than CMake. CMake is the
  project's build system; the Rust subsystem is a leaf CMake
  target that happens to call `cargo` internally.
- **Rebuilding the world:** if any Rust crate's `.rs` file
  changes, `cargo` rebuilds it and the kernel ELF relinks.
  CMake tracks this via the `add_custom_command`'s DEPENDS
  list — every `.rs` file must be listed there. Missing a
  file means stale builds.
- **Interop with the Win32 subsystem:** none, ever. The
  Win32 subsystem's C++ code paths are tuned to the PE ABI
  and Windows' own memory model; inserting Rust there would
  add a translation tax for no safety gain (the attack
  surface is the PE input, which we already parse
  defensively in C++).

**See also:**

- `ai-bloat-pattern.md` — the general "don't add layers
  without a consumer" rule applies double to introducing a
  second language.
- `hardware-target-matrix.md` — filesystem / USB / net tiers
  are the subsystem candidates this plan scopes.
- CLAUDE.md §"Coding Standards" — the one-paragraph policy
  this entry expands.
