#!/bin/sh
# Offline only: no interface, firmware command, EFI, or router operations.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
security_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ax201-personal-security.XXXXXX")
trap 'rm -rf "$security_tmp"' EXIT HUP INT TERM

clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/wcl_backend.cpp \
  native/tests/wcl_test.cpp -o "$security_tmp/wcl"
"$security_tmp/wcl"
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/tests/wcl_security_test.cpp \
  -o "$security_tmp/wcl-security"
"$security_tmp/wcl-security"
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/key_material.cpp native/tests/key_material_test.cpp \
  -o "$security_tmp/key-material"
"$security_tmp/key-material"
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/tests/pmf_crypto_policy_test.cpp \
  -o "$security_tmp/pmf-policy"
"$security_tmp/pmf-policy"
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/wcl_backend.cpp \
  native/tests/hidden_network_test.cpp -o "$security_tmp/hidden-network"
"$security_tmp/hidden-network"
python3 native/tests/test_hidden_scan_production.py
python3 native/tests/test_native_personal_join.py
python3 native/tests/test_native_security_stop.py
python3 native/tests/test_native_security_events.py
python3 native/tests/test_airport_stop_busy_retains.py
python3 native/tests/test_pmf_production_crypto.py
python3 native/tests/test_pmf_gate_lifecycle.py
python3 native/tests/test_pmf_ack_completion.py
python3 native/tests/test_pmf_reset_retry_body.py
python3 native/tests/test_iwx_transition_gate.py
python3 native/tests/test_sta_sa_query.py
sh third_party/sae/tests/run_host_tests.sh
"${SAE_ORACLE_PYTHON:-python3}" native/tests/test_sae_eapol_reference.py
printf '%s\n' 'PASS: offline personal-security suite'
