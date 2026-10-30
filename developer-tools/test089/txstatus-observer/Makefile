HOST_CC ?= clang
ZIG ?= zig
CFLAGS_COMMON = -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
SOURCES = txstatus_observer.c probe_frame.c radiotap_parser.c
BUILD = build
HOST_TEST_BIN = $(BUILD)/test089-host-test
LINUX_BIN = $(BUILD)/test089-txstatus-observer-linux
AARCH64_BIN = $(BUILD)/test089-txstatus-observer-aarch64-linux-musl

.PHONY: host-test linux aarch64 clean

$(BUILD):
	mkdir -p $(BUILD)

$(HOST_TEST_BIN): test_host.c probe_frame.c radiotap_parser.c probe_frame.h radiotap_parser.h | $(BUILD)
	$(HOST_CC) $(CFLAGS_COMMON) test_host.c probe_frame.c radiotap_parser.c -o $@

host-test: $(HOST_TEST_BIN)
	./$(HOST_TEST_BIN)
	python3 test_source_parity.py

linux: $(SOURCES) probe_frame.h radiotap_parser.h | $(BUILD)
	$(HOST_CC) $(CFLAGS_COMMON) $(SOURCES) -o $(LINUX_BIN)
	file $(LINUX_BIN)

aarch64: $(SOURCES) probe_frame.h radiotap_parser.h | $(BUILD)
	$(ZIG) cc -target aarch64-linux-musl -static $(CFLAGS_COMMON) -D_FORTIFY_SOURCE=2 $(SOURCES) -o $(AARCH64_BIN)
	file $(AARCH64_BIN)

clean:
	rm -rf $(BUILD)
