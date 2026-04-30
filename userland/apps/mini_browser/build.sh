#!/usr/bin/env bash
#
# Rebuild mini_browser.exe (Windows PE32+) from browser.c using mingw-w64.
# The kernel build embeds the prebuilt .exe directly so this script only
# needs to run when browser.c changes.
#
# Required: gcc-mingw-w64-x86-64 (Ubuntu: apt-get install gcc-mingw-w64-x86-64).
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
x86_64-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe \
    -e mainCRTStartup \
    -Wl,--subsystem,console -Wl,--entry,mainCRTStartup \
    -o browser.exe browser.c \
    -lkernel32 -lws2_32
echo "Built: $(ls -la browser.exe | awk '{print $5}') bytes"
echo "Imports:"
x86_64-w64-mingw32-objdump -p browser.exe | grep -E "DLL Name|^\s+[0-9a-f]+\s+[0-9]+\s+\w" | head -30
