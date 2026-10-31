#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")"
mkdir -p build
chmod 700 build
clang++ -std=c++11 -Wall -Wextra -Wpedantic -Werror -O2 \
  -nostdinc++ -ffreestanding -fno-exceptions -fno-rtti -fno-builtin \
  -fno-stack-protector \
  -c core_header_check.cpp \
  -o build/core_header_check.o
undefined_symbols=$(nm -u build/core_header_check.o)
if [ -n "$undefined_symbols" ]; then
  printf '%s\n' "Unexpected core runtime references:" "$undefined_symbols" >&2
  exit 1
fi
printf '%s\n' "PASS freestanding core has no undefined runtime references"
clang++ -std=c++11 -Wall -Wextra -Wpedantic -Werror -O2 -pthread \
  -DTEST093_ENABLE_TEST_PROBE \
  completion_copy_fence_test.cpp \
  -o build/completion_copy_fence_test
./build/completion_copy_fence_test
