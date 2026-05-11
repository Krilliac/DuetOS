/*
 * DuetOS — first portable native ELF demo, v0.
 *
 * Built by `tools/build/build-native-app.sh hello_native` →
 * embedded into the kernel ramfs by `kernel/CMakeLists.txt` →
 * spawned by `kernel/core/main.cpp` after init via
 * `core::SpawnElfFile`. The boot smoke greps for the
 * `[hello-native] ` sentinel below to confirm the portable-app
 * pipeline survives every regression.
 *
 * Demonstrates:
 *   - The userland libc print helpers (`println`, `print_fmt`).
 *   - `getpid()` round-trip — proves the process model is
 *     reachable from a hand-written native binary.
 *   - Clean exit with a sentinel rc so the kernel reaper logs
 *     it identifiably.
 *
 * NOT a window — native GUI apps need a userland widget library
 * (Native-Apps wiki page documents the migration plan).
 */

#include "stdio.h"
#include "unistd.h"

int main(void)
{
    println("[hello-native] portable native ELF spawned");
    print_fmt("[hello-native] pid=%d exit-rc=%x\n", getpid(), 0xCAFEU);
    return 0xCAFE;
}
