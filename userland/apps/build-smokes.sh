#!/usr/bin/env bash
#
# Rebuild every PE smoke app via mingw-w64. The kernel build embeds
# the prebuilt .exe files directly so this script only needs to run
# when one of the C sources changes.
#
# Required: gcc-mingw-w64-x86-64 (Ubuntu: apt-get install gcc-mingw-w64-x86-64).
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

CC=x86_64-w64-mingw32-gcc
COMMON_FLAGS=(
    -nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe
    -e mainCRTStartup -Wl,--subsystem,console -Wl,--entry,mainCRTStartup
)

declare -A APPS=(
    [mini_browser]="-lkernel32 -lws2_32"
    [crypto_smoke]="-lkernel32 -lbcrypt -ladvapi32"
    [paths_smoke]="-lkernel32 -lshlwapi"
    [time_smoke]="-lkernel32 -lwinmm"
    [wininet_smoke]="-lkernel32 -lwininet"
    [iphlpapi_smoke]="-lkernel32 -liphlpapi"
    [string_smoke]="-lkernel32 -luser32"
    [mem_smoke]="-lkernel32"
    [fs_smoke]="-lkernel32"
    [registry_smoke]="-lkernel32 -ladvapi32"
    [handle_smoke]="-lkernel32"
    [process_smoke]="-lkernel32"
    [module_smoke]="-lkernel32"
    [env_smoke]="-lkernel32"
    [debug_smoke]="-lkernel32"
    [codepage_smoke]="-lkernel32"
    [rng_smoke]="-lkernel32 -lbcrypt -ladvapi32"
    [version_smoke]="-lkernel32 -lversion"
    [psapi_smoke]="-lkernel32 -lpsapi"
    [com_smoke]="-lkernel32 -lole32"
    [dbghelp_smoke]="-lkernel32 -ldbghelp"
    [winhttp_smoke]="-lkernel32 -lwinhttp"
)

for app in "${!APPS[@]}"; do
    src=$(ls "$app"/*.c | head -1)
    if [[ -z "$src" ]]; then
        echo "SKIP: $app (no .c source found)"
        continue
    fi
    # The kernel CMake embed function looks for <app>/<app>.exe;
    # mini_browser predates that convention and uses browser.exe.
    out="$app/${app}.exe"
    if [[ "$app" == "mini_browser" ]]; then
        out="$app/browser.exe"
    fi
    "$CC" "${COMMON_FLAGS[@]}" -o "$out" "$src" ${APPS[$app]}
    printf '  %-16s %d bytes\n' "$app" "$(stat -c%s "$out")"
done
echo "All smoke PEs built."
