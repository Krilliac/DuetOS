#pragma once

/*
 * DuetOS — compiler attribute shims.
 *
 * DUETOS_NO_SANITIZE_WRAP marks a function whose integer arithmetic
 * is intentionally modular (wrap-on-overflow) or whose shift amounts
 * are spec-defined — cryptographic primitives, PRNGs, ring-buffer
 * index math, CRC/checksum folds. Such code is correct *because* it
 * wraps; it is not a bug. Under the opt-in `-fsanitize=integer`
 * family (x86_64-debug-san) every such operation would otherwise
 * emit a runtime report. A memory-hard KDF (Argon2id → Blake2b)
 * runs millions of these per boot, which floods the serial console
 * and starves the boot of its completion window — see the
 * `DUETOS_ENABLE_UBSAN_INTEGER` rationale in kernel/CMakeLists.txt.
 *
 * The attribute disables ONLY the overflow/shift classes that the
 * wrapping is defined to exercise. Bounds, null, alignment and
 * object-size checks stay live, so a real OOB inside an annotated
 * crypto routine is still caught. Apply it narrowly — to the
 * mixing/round functions that wrap by design, not to whole TUs.
 *
 * No-op unless the integer sanitizer is actually compiled in, so
 * release and the default debug build are byte-identical.
 */

#if defined(DUETOS_UBSAN) && defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define DUETOS_NO_SANITIZE_WRAP                                                                                        \
    __attribute__((no_sanitize("shift", "unsigned-shift-base", "unsigned-integer-overflow", "signed-integer-overflow")))
#endif
#endif

#ifndef DUETOS_NO_SANITIZE_WRAP
#define DUETOS_NO_SANITIZE_WRAP
#endif
