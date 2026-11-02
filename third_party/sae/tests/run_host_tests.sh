#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/itlwm-sae-test.XXXXXX")
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM
mkdir -p "$test_tmp/include/sys"
cat > "$test_tmp/include/sys/systm.h" <<'EOF'
#include <stdint.h>
#include <string.h>
#include <strings.h>
EOF

cd "$repo_root"
cc=${CC:-clang}
cxx=${CXX:-clang++}
base_flags="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I$test_tmp/include -Ithird_party/sae/hostap -Ithird_party/sae/mbedtls/include -Iitl80211/openbsd -Iitl80211/openbsd/crypto -Iitl80211/openbsd/sys"
wrapper_flags="-Ithird_party/sae/tests/host_shims $base_flags"

crypto_objects=

for name in bignum bignum_core bignum_mod bignum_mod_raw constant_time ecp ecp_curves platform_util sae_mbedtls_port; do
	$cc -std=c99 -Wall -Wextra -Werror $base_flags \
		-c "third_party/sae/mbedtls/library/$name.c" \
		-o "$test_tmp/$name.o"
	crypto_objects="$crypto_objects $test_tmp/$name.o"
done

for name in sae dragonfly sae_mbedtls sae_port; do
	$cc -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter $base_flags \
		-c "third_party/sae/hostap/$name.c" \
		-o "$test_tmp/$name.o"
	crypto_objects="$crypto_objects $test_tmp/$name.o"
done

$cc -std=c99 -Wall -Wextra -Werror $base_flags \
	-c third_party/sae/tests/sae_engine_test.c \
	-o "$test_tmp/sae_engine_test.o"
$cc -std=c99 -Wall -Wextra -Werror $base_flags \
	-c third_party/sae/tests/sae_hostap_kat.c \
	-o "$test_tmp/sae_hostap_kat.o"

# The production target compiles this existing .c file as C++; keep that ABI.
$cxx -x c++ -std=c++17 -Wall -Wextra -Werror -Wno-array-parameter \
	-Wno-unused-parameter $base_flags \
	-c itl80211/openbsd/crypto/sha2.c -o "$test_tmp/sha2.o"
$cxx -std=c++17 -Wall -Wextra -Werror $base_flags \
	-c third_party/sae/hostap/sae_sha2_bridge.cpp \
	-o "$test_tmp/sae_sha2_bridge.o"
$cxx -x c++ -std=c++17 -Wall -Wextra -Werror \
	-Wno-array-parameter -Wno-unused-parameter -DAIRPORT_TAHOE=1 \
	$wrapper_flags -c third_party/sae/tests/ieee80211_sae_wrapper_test.cpp \
	-o "$test_tmp/ieee80211_sae_wrapper_test.o"

$cxx -fsanitize=address,undefined -fno-omit-frame-pointer \
	$crypto_objects "$test_tmp/sha2.o" "$test_tmp/sae_sha2_bridge.o" \
	"$test_tmp/sae_engine_test.o" -o "$test_tmp/sae_engine_test"
"$test_tmp/sae_engine_test"
$cxx -fsanitize=address,undefined -fno-omit-frame-pointer \
	$crypto_objects "$test_tmp/sha2.o" "$test_tmp/sae_sha2_bridge.o" \
	"$test_tmp/sae_hostap_kat.o" -o "$test_tmp/sae_hostap_kat"
"$test_tmp/sae_hostap_kat"
$cxx -fsanitize=address,undefined -fno-omit-frame-pointer \
	$crypto_objects "$test_tmp/sha2.o" "$test_tmp/sae_sha2_bridge.o" \
	"$test_tmp/ieee80211_sae_wrapper_test.o" \
	-o "$test_tmp/ieee80211_sae_wrapper_test"
"$test_tmp/ieee80211_sae_wrapper_test"
