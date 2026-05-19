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

LOADER   := $(KERNEL)/loader
EXEC_META := $(LOADER)/exec_meta_rust

# rustc is only needed for fuzz_pe (the PE validator delegates its
# prefix/image gate to the no_std duetos_exec_meta Rust crate).
RUSTC    := rustc
RUST_EDITION := 2021

BIN := build
FS       := $(KERNEL)/fs
UTIL     := $(KERNEL)/util

EXFAT_RUST := $(FS)/exfat_rust

HARNESSES := $(BIN)/fuzz_iwl_fw $(BIN)/fuzz_rtl_fw $(BIN)/fuzz_bcm_fw $(BIN)/fuzz_eapol \
             $(BIN)/fuzz_pe $(BIN)/fuzz_elf $(BIN)/fuzz_gpt $(BIN)/fuzz_fat32 \
             $(BIN)/fuzz_exfat

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

# --- PE/COFF loader fuzzer ---------------------------------------
#
# pe_loader.cpp is one TU pulling the whole mm/proc/win32 surface;
# host_shim/pe_stubs.cpp resolves the PeLoad-only symbols (they
# abort if the pure validate/report path ever reaches them). The
# DOS/COFF prefix + opt-header gate lives in the no_std
# duetos_exec_meta Rust crate — built here as an rlib + a
# panic=abort staticlib wrapper so a Rust-side overflow/index bug
# also aborts as a libFuzzer crash.
$(BIN)/libduetos_exec_meta.rlib: $(EXEC_META)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_exec_meta -O $< -o $@

$(BIN)/libduetos_exec_meta_fuzz.a: host_shim/exec_meta_fuzz_shim.rs \
		$(BIN)/libduetos_exec_meta.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_exec_meta=$(BIN)/libduetos_exec_meta.rlib $< -o $@

$(BIN)/fuzz_pe: fuzz_pe.cpp $(LOADER)/pe_loader.cpp $(LOADER)/pe_exports.cpp \
		host_shim/pe_stubs.cpp $(BIN)/libduetos_exec_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(EXEC_META)/include $^ -o $@

# ELF64 loader: native peer of the PE loader. Shares the Rust
# exec_meta validator and the kernel-symbol stub TU (ElfLoad's
# mm/security deps overlap PeLoad's).
$(BIN)/fuzz_elf: fuzz_elf.cpp $(LOADER)/elf_loader.cpp \
		host_shim/pe_stubs.cpp $(BIN)/libduetos_exec_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(EXEC_META)/include $^ -o $@

# GPT partition-table parser. Serves the fuzz input as a read-only
# disk via host_shim/drivers/storage/block.h; links the real
# CRC32 the parser validates headers + entry array against.
$(BIN)/fuzz_gpt: fuzz_gpt.cpp $(FS)/gpt.cpp $(UTIL)/crc32.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# FAT32 volume parser. Same read-only-disk shim as fuzz_gpt; the
# probe spans fat32.cpp plus the lookup/dir/read companion TUs.
$(BIN)/fuzz_fat32: fuzz_fat32.cpp $(FS)/fat32.cpp $(FS)/fat32_lookup.cpp \
		$(FS)/fat32_dir.cpp $(FS)/fat32_read.cpp host_shim/fs_stubs.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# exFAT volume parser. Byte parsing is the no_std duetos_exfat
# Rust crate (rlib + panic=abort staticlib wrapper, same recipe
# as duetos_exec_meta) so a Rust-side bounds/overflow bug also
# aborts as a libFuzzer crash.
$(BIN)/libduetos_exfat.rlib: $(EXFAT_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_exfat -O $< -o $@

$(BIN)/libduetos_exfat_fuzz.a: host_shim/exfat_fuzz_shim.rs \
		$(BIN)/libduetos_exfat.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_exfat=$(BIN)/libduetos_exfat.rlib $< -o $@

$(BIN)/fuzz_exfat: fuzz_exfat.cpp $(FS)/exfat.cpp host_shim/fs_stubs.cpp \
		$(BIN)/libduetos_exfat_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(EXFAT_RUST)/include $^ -o $@

# Each run-* keeps a persistent corpus and stops after 60 s.
# run-pe seeds the corpus first (see seeds/gen_pe_seeds.py) so the
# fuzzer starts past the DOS/COFF prefix gate.
run-pe: $(BIN)/fuzz_pe
	@mkdir -p corpus/pe
	@python3 seeds/gen_pe_seeds.py corpus/pe
	$(BIN)/fuzz_pe -max_len=131072 -max_total_time=60 -print_final_stats=1 corpus/pe

run-elf: $(BIN)/fuzz_elf
	@mkdir -p corpus/elf
	@python3 seeds/gen_elf_seeds.py corpus/elf
	$(BIN)/fuzz_elf -max_total_time=60 -print_final_stats=1 corpus/elf

run-gpt: $(BIN)/fuzz_gpt
	@mkdir -p corpus/gpt
	@python3 seeds/gen_gpt_seeds.py corpus/gpt
	$(BIN)/fuzz_gpt -max_len=262144 -max_total_time=60 -print_final_stats=1 corpus/gpt

run-fat32: $(BIN)/fuzz_fat32
	@mkdir -p corpus/fat32
	@python3 seeds/gen_fat32_seeds.py corpus/fat32
	$(BIN)/fuzz_fat32 -max_len=262144 -max_total_time=60 -print_final_stats=1 corpus/fat32

run-exfat: $(BIN)/fuzz_exfat
	@mkdir -p corpus/exfat
	@python3 seeds/gen_exfat_seeds.py corpus/exfat
	$(BIN)/fuzz_exfat -max_len=262144 -max_total_time=60 -print_final_stats=1 corpus/exfat

run-%: $(BIN)/fuzz_%
	@mkdir -p corpus/$*
	$< -max_total_time=60 -print_final_stats=1 corpus/$*

clean:
	rm -rf $(BIN)
