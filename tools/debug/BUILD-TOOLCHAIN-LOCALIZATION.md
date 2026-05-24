# Localizing build / toolchain / linker failures in DuetOS

For "ninja: build stopped: subcommand failed exit code 127"; for
unresolved-symbol link errors; for cmake configure failures; for
"my edit makes the kernel un-buildable but the diff looks fine"; for
the "release builds clean but debug doesn't (or vice-versa)" class.

This is the class PR #336's `llvm-objcopy` symlink miss landed in —
worth its own methodology.

---

## PROMPT (paste verbatim)

```text
DuetOS won't build. Localize using the build-fail methodology in
tools/debug/BUILD-TOOLCHAIN-LOCALIZATION.md.

SYMPTOM:
  <paste the ninja error line(s). Include `FAILED:` line, the immediately-
   preceding stdout (which usually carries the actual error), and exit
   code. If multiple FAILED entries, paste all.>

==========================================================================
STEP 1 — Classify the failure.

  exit 127: command-not-found
    A tool the script needs isn't on PATH. PR #336 hit llvm-objcopy +
    llvm-nm + llvm-addr2line. Other usual suspects: x86_64-w64-mingw32-gcc,
    i686-w64-mingw32-gcc, grub-mkrescue, xorriso, mtools.
    Resolution: install the package OR add the symlink to
    /usr/local/bin (see .github/workflows/build.yml install-toolchain
    steps for the canonical pattern).

  exit 1 with "undefined reference to ...": link error
    Symbol declared but not defined OR not in the link line.
    grep -rn "<symbol>" kernel/ to find the decl AND the impl. If the
    impl exists but isn't linked, check CMakeLists.txt GLOB or explicit
    source list — a .cpp added to the tree but missed by the build
    system is a classic kernel-link miss.

  exit 1 with "use of undeclared identifier": compile error
    Header not included OR namespace wrong. clang-format / clang-tidy
    in CI catches some of these; if they didn't, the include is
    wrong. Use `grep -rn "<identifier>" kernel/` to find its real
    home.

  exit 1 with "relocation against ... in file linked without -Bsymbolic"
    Linker mode mismatch. Kernel is freestanding -static — every TU
    must be -fPIC=no. Check `target_compile_options` on the offending
    TU's library target.

  exit 0 BUT a *.iso / *.elf is empty / wrong-size:
    Stage-2 (image assembly) failed silently. xorriso / grub-mkrescue
    can exit success on a degenerate input. Check the artefact:
    `file build/x86_64-release/duetos.iso` — non-ISO output is the
    symptom.

==========================================================================
STEP 2 — Reproduce ONE-SHOT.

  Don't `cmake --build` the whole tree — that can take many minutes.
  Instead, target the failing object:

  cmake --build build/x86_64-debug --target kernel/CMakeFiles/duetos-kernel.dir/path/to/file.cpp.obj 2>&1

  Or the failing custom command's output:

  cmake --build build/x86_64-debug --target build/x86_64-debug/kernel/generated_linux_vdso.h 2>&1

==========================================================================
STEP 3 — Identify "what changed".

  git log --oneline -p -- <failing-file-path> | head -50
  git log --oneline -- <CMakeLists.txt-or-toolchain-file>
  git log --since="2 days" --oneline -- tools/build/

  Common landings that break builds:
  - New `build-*.sh` helper that needs a tool not yet in CI install line.
  - New `find_package(... REQUIRED)` in CMakeLists.txt that doesn't have
    a fallback for the dev environment.
  - A header that includes a kernel-internal header from userland code.

==========================================================================
STEP 4 — Toolchain version mismatch checks.

  /usr/local/bin/clang --version    # expect 18.x
  /usr/lib/llvm-18/bin/ld.lld --version
  cmake --version                   # expect 3.25+
  ninja --version
  ls /usr/bin/x86_64-w64-mingw32-gcc  # mingw for PE smoke fixtures

  If a version is wrong, the build script's `${TOOL:-default}` usually
  picks up the right one — but ONLY if the prefixed binary is symlinked
  or on PATH. CI's install step in .github/workflows/build.yml is the
  source of truth; mirror it locally.

==========================================================================
STEP 5 — Per-preset divergence.

  If x86_64-release builds and x86_64-debug doesn't (or vice-versa):
    - Check CMakePresets.json for the per-preset flags.
    - Common cause: debug enables KASAN / UBSAN runtime, which links
      against libclang_rt.* which only exists if libclang-rt-18-dev
      is installed.
    - Or: release uses LTO and a TU needs --no-lto for some asm.
    - Or: debug has a self-test in a TU that release doesn't compile,
      and the self-test references a symbol only the debug build has.

==========================================================================
STEP 6 — Fix at the right layer.

  Missing tool: edit .github/workflows/build.yml install line. ALSO
    mirror to tools/build/wsl-kernel-build*.sh (the dev workflow).
    Don't pick one — both must work.

  Linker missing symbol: add the .cpp to CMakeLists.txt's source list
    OR fix the GLOB pattern. NEVER add a stub `extern "C" void
    MissingSymbol() {}` to silence the linker — that masks the real
    bug.

  Per-preset divergence: prefer making both presets buildable. If you
    must conditionally exclude a TU, gate at CMake level (not
    `#ifdef DUETOS_RELEASE` inside the .cpp).

==========================================================================
STEP 7 — Validate.

  bash tools/build/wsl-kernel-build.sh         # release
  bash tools/build/wsl-kernel-build-debug.sh   # debug
  bash tools/build/wsl-build-isos.sh           # both ISOs as the
                                               # end-to-end check

  Then push to CI, watch the workflow run, expect all 6 build jobs
  green (build debug, build release, 4× flavor matrix).

==========================================================================
STEP 8 — Save memory:
  Capture: the failing tool / symbol / preset, the install line you
  added, the file you edited. Future build breaks of the same class
  shortcut to the same fix.
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| exit 127, llvm-* not found | install line missing symlink | grep `sudo ln -sf /usr/bin/llvm-` in build.yml |
| undefined reference to a function you can see in source | TU not in CMake GLOB | kernel/CMakeLists.txt file(GLOB_RECURSE ...) |
| debug builds but release fails | LTO pass exposed a UB the optimizer relied on | -fno-strict-aliasing / -fno-builtin per-TU |
| release builds but debug fails | sanitizer runtime missing | apt-get install libclang-rt-18-dev |
| 0-byte ISO output | grub-mkrescue silent fail | run with --verbose, check stderr |
| relocation R_X86_64_GOTPCREL | PIC compile, non-PIC link | -fno-pic + -no-pie on the target |
