#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build the pinned SAE C implementation without the driver's C++ prefix header.
set -euo pipefail

: "${PROJECT_DIR:?PROJECT_DIR is required}"
: "${DERIVED_FILE_DIR:?DERIVED_FILE_DIR is required}"
: "${ARCHS:?ARCHS is required}"
if [[ "$ARCHS" != "x86_64" ]]; then
    echo "AX201 native SAE currently builds for x86_64 only" >&2
    exit 1
fi

sae_dir="$PROJECT_DIR/third_party/sae"
sae_objects="$DERIVED_FILE_DIR/AX201SAE"
sdk_headers="$PROJECT_DIR/MacKernelSDK/Headers"
clang_resource="$(xcrun clang -print-resource-dir)"
mkdir -p "$sae_objects"

sae_sources=(
    hostap/sae.c
    hostap/dragonfly.c
    hostap/sae_port.c
    hostap/sae_mbedtls.c
    mbedtls/library/bignum.c
    mbedtls/library/bignum_core.c
    mbedtls/library/bignum_mod.c
    mbedtls/library/bignum_mod_raw.c
    mbedtls/library/constant_time.c
    mbedtls/library/ecp.c
    mbedtls/library/ecp_curves.c
    mbedtls/library/platform_util.c
    mbedtls/library/sae_mbedtls_port.c
)
sae_flags=(
    -arch x86_64 -x c -std=c11 -O2 -mkernel -mno-red-zone
    -fno-builtin -fno-common -fno-stack-protector -fvisibility=hidden
    -DKERNEL=1 -DKERNEL_PRIVATE=1 -DDRIVER_PRIVATE=1 -DAIRPORT_TAHOE=1
    -nostdinc -isystem "$clang_resource/include"
    -isystem "$sdk_headers" -isystem "$sdk_headers/bsd"
    -isystem "$sdk_headers/iokit" -isystem "$sdk_headers/libkern"
    -I "$sae_dir/hostap" -I "$sae_dir/mbedtls/include"
    -Werror=implicit-function-declaration -Werror=incompatible-pointer-types
)
sae_object_files=()
for sae_source in "${sae_sources[@]}"; do
    sae_object="$sae_objects/${sae_source//\//_}.o"
    xcrun clang "${sae_flags[@]}" -c "$sae_dir/$sae_source" -o "$sae_object"
    sae_object_files+=("$sae_object")
done

# Replace the archive only after every translation unit compiled successfully.
sae_archive="$DERIVED_FILE_DIR/libAX201SAE.a"
rm -f "$sae_archive.new"
xcrun ar rcs "$sae_archive.new" "${sae_object_files[@]}"
mv -f "$sae_archive.new" "$sae_archive"
