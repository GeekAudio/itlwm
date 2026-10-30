HOST_CC ?= clang
ZIG ?= zig
CFLAGS_COMMON = -std=c11 -Os -Wall -Wextra -Werror -fstack-protector-strong
SOURCE = awdl_probe_sender.c
BUILD = build
HOST_TEST_BIN = $(BUILD)/awdl_probe_sender-host-test
TARGET_BIN = $(BUILD)/awdl_probe_sender-aarch64-linux-musl

.PHONY: host-test aarch64 clean

$(BUILD):
	mkdir -p $(BUILD)

$(HOST_TEST_BIN): $(SOURCE) test_sender_host_negative.py | $(BUILD)
	$(HOST_CC) $(CFLAGS_COMMON) -DSENDER_HOST_TEST $(SOURCE) -o $@

host-test: $(HOST_TEST_BIN)
	python3 test_sender_host_negative.py $(HOST_TEST_BIN)

aarch64: $(SOURCE) | $(BUILD)
	$(ZIG) cc -target aarch64-linux-musl -static $(CFLAGS_COMMON) -D_FORTIFY_SOURCE=2 $(SOURCE) -o $(TARGET_BIN)
	file $(TARGET_BIN)

clean:
	rm -rf $(BUILD) build-host-test
