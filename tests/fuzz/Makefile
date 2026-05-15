# tests/fuzz/Makefile
#
# Builds the libFuzzer-driven harnesses for the DuetOS external-input
# parsers. Host clang only (libFuzzer + ASan + UBSan); the kernel-only
# headers are stubbed by host_shim/.
#
#   make                 # build every C++ harness
#   make run-eapol        # fuzz one for 60 s (corpus/<name>/ persists)
#   make run-iwl_fw
#   make run-rtl_fw
#   make run-bcm_fw
#   make clean
#
# The 802.11 management-frame walker (BeaconParse) is NOT here: its
# parsing logic now lives in the memory-safe `duetos_wifi80211` Rust
# crate (kernel/net/wifi80211_rust/), which is fuzzed with cargo-fuzz,
# not this C++ host harness. The C++ beacon shim is a thin FFI caller
# with no byte-level parsing left to fuzz.

# libFuzzer is clang-only; pin clang++ and ignore a g++ in the
# environment. Override on the command line if needed: make CXX=clang++-18
CXX      := clang++
KERNEL   := $(abspath ../../kernel)
CRYPTO   := $(KERNEL)/crypto
WIRELESS := $(KERNEL)/net/wireless
NETDRV   := $(KERNEL)/drivers/net

CXXFLAGS := -std=c++23 -g -O1 -fno-omit-frame-pointer -DDUETOS_HOST_TEST \
            -fsanitize=fuzzer,address,undefined \
            -I host_shim -I $(KERNEL)

BIN := build
HARNESSES := $(BIN)/fuzz_iwl_fw $(BIN)/fuzz_rtl_fw $(BIN)/fuzz_bcm_fw $(BIN)/fuzz_eapol

.PHONY: all clean
all: $(HARNESSES)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/fuzz_iwl_fw: fuzz_iwl_fw.cpp $(NETDRV)/iwlwifi_fw.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BIN)/fuzz_rtl_fw: fuzz_rtl_fw.cpp $(NETDRV)/rtl88xx_fw.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BIN)/fuzz_bcm_fw: fuzz_bcm_fw.cpp $(NETDRV)/bcm43xx_fw.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# EapolKeyParse pulls HMAC-SHA1/SHA256 (MIC verify) transitively.
$(BIN)/fuzz_eapol: fuzz_eapol.cpp $(WIRELESS)/eapol.cpp \
		$(CRYPTO)/hmac.cpp $(CRYPTO)/sha1.cpp $(CRYPTO)/sha256.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Each run-* keeps a persistent corpus and stops after 60 s.
run-%: $(BIN)/fuzz_%
	@mkdir -p corpus/$*
	$< -max_total_time=60 -print_final_stats=1 corpus/$*

clean:
	rm -rf $(BIN)
