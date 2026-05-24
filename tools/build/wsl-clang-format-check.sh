#!/usr/bin/env bash
# Run clang-format --dry-run over the whole kernel + userland and
# emit a list of files with violations. Helper for the
# result-checks-and-guards session's pre-push signal sweep.
set -euo pipefail
cd ~/source/DuetOS
find kernel userland \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror 2>&1 \
  | grep 'error: code should be clang-formatted' \
  | awk -F: '{print $1}' \
  | sort -u
