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
NTFS_RUST := $(FS)/ntfs_rust
EXT4_RUST := $(FS)/ext4_rust
NET := $(KERNEL)/net
NET_PARSERS_RUST := $(NET)/parsers_rust
IMG_META_RUST := $(UTIL)/img_meta_rust

HARNESSES := $(BIN)/fuzz_iwl_fw $(BIN)/fuzz_rtl_fw $(BIN)/fuzz_bcm_fw $(BIN)/fuzz_eapol \
             $(BIN)/fuzz_pe $(BIN)/fuzz_elf $(BIN)/fuzz_gpt $(BIN)/fuzz_fat32 \
             $(BIN)/fuzz_exfat $(BIN)/fuzz_ntfs $(BIN)/fuzz_ext4 $(BIN)/fuzz_net \
             $(BIN)/fuzz_deflate $(BIN)/fuzz_gzip $(BIN)/fuzz_zip \
             $(BIN)/fuzz_bmp $(BIN)/fuzz_tga $(BIN)/fuzz_jpeg $(BIN)/fuzz_png \
             $(BIN)/fuzz_asn1 $(BIN)/fuzz_x509 $(BIN)/fuzz_fw_pkg \
             $(BIN)/fuzz_pe_exports $(BIN)/fuzz_vt $(BIN)/fuzz_disasm \
             $(BIN)/fuzz_edid $(BIN)/fuzz_cea861 \
             $(BIN)/fuzz_usbclass $(BIN)/fuzz_usbhid \
             $(BIN)/fuzz_tls

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

# NTFS volume parser. Same recipe as fuzz_exfat — byte parsing is
# the no_std duetos_ntfs Rust crate.
$(BIN)/libduetos_ntfs.rlib: $(NTFS_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_ntfs -O $< -o $@

$(BIN)/libduetos_ntfs_fuzz.a: host_shim/ntfs_fuzz_shim.rs \
		$(BIN)/libduetos_ntfs.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_ntfs=$(BIN)/libduetos_ntfs.rlib $< -o $@

$(BIN)/fuzz_ntfs: fuzz_ntfs.cpp $(FS)/ntfs.cpp host_shim/fs_stubs.cpp \
		$(BIN)/libduetos_ntfs_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(NTFS_RUST)/include $^ -o $@

# ext4 volume parser (read-only Linux-interop tier). Same recipe.
$(BIN)/libduetos_ext4.rlib: $(EXT4_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_ext4 -O $< -o $@

$(BIN)/libduetos_ext4_fuzz.a: host_shim/ext4_fuzz_shim.rs \
		$(BIN)/libduetos_ext4.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_ext4=$(BIN)/libduetos_ext4.rlib $< -o $@

$(BIN)/fuzz_ext4: fuzz_ext4.cpp $(FS)/ext4.cpp host_shim/fs_stubs.cpp \
		$(BIN)/libduetos_ext4_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(EXT4_RUST)/include $^ -o $@

# Network L2/L3 ingest: NetStackInjectRx -> ARP / IPv4 / ICMP /
# UDP / TCP byte walkers. The DHCP-option / DNS-name parsing is
# the no_std duetos_net_parsers Rust crate (same rlib +
# panic=abort staticlib recipe). net_stubs.cpp resolves the
# NIC/Wi-Fi/scheduler/pipe symbols the socket TU drags in but the
# RX parse path never reaches.
$(BIN)/libduetos_net_parsers.rlib: $(NET_PARSERS_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_net_parsers -O $< -o $@

$(BIN)/libduetos_net_parsers_fuzz.a: host_shim/net_parsers_fuzz_shim.rs \
		$(BIN)/libduetos_net_parsers.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_net_parsers=$(BIN)/libduetos_net_parsers.rlib $< -o $@

$(BIN)/fuzz_net: fuzz_net.cpp $(NET)/stack.cpp $(NET)/firewall.cpp \
		$(NET)/socket.cpp $(NET)/tcp.cpp $(NET)/tcp_segment.cpp $(NET)/tcp_timer.cpp \
		host_shim/net_stubs.cpp host_shim/fs_stubs.cpp \
		$(BIN)/libduetos_net_parsers_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(NET_PARSERS_RUST)/include $^ -o $@

# --- util decompression / container parsers ----------------------
#
# Pure functions over a (ptr,len) buffer that consume bytes from
# inside a PNG IDAT / gzip-initramfs / ZIP on a USB stick. No Rust
# side; host_shim/core/panic.h + serial.h resolve the only kernel
# deps. The static output ceilings live in the harness sources.
$(BIN)/fuzz_deflate: fuzz_deflate.cpp $(UTIL)/deflate.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BIN)/fuzz_gzip: fuzz_gzip.cpp $(UTIL)/gzip.cpp $(UTIL)/deflate.cpp \
		$(UTIL)/adler32.cpp $(UTIL)/crc32.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BIN)/fuzz_zip: fuzz_zip.cpp $(UTIL)/zip.cpp $(UTIL)/deflate.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- image decoders ----------------------------------------------
#
# bmp/tga/jpeg/png delegate header validation to the no_std
# duetos_img_meta Rust crate (rlib + panic=abort staticlib
# wrapper, same recipe as duetos_exec_meta) so a Rust-side
# bounds/overflow bug in the header walker also aborts as a
# libFuzzer crash. The C++ side keeps the heavy decode (zlib /
# scanline filter / pixel copy).
$(BIN)/libduetos_img_meta.rlib: $(IMG_META_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_img_meta -O $< -o $@

$(BIN)/libduetos_img_meta_fuzz.a: host_shim/img_meta_fuzz_shim.rs \
		$(BIN)/libduetos_img_meta.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_img_meta=$(BIN)/libduetos_img_meta.rlib $< -o $@

$(BIN)/fuzz_bmp: fuzz_bmp.cpp $(UTIL)/bmp.cpp \
		$(BIN)/libduetos_img_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(IMG_META_RUST)/include $^ -o $@

$(BIN)/fuzz_tga: fuzz_tga.cpp $(UTIL)/tga.cpp \
		$(BIN)/libduetos_img_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(IMG_META_RUST)/include $^ -o $@

$(BIN)/fuzz_jpeg: fuzz_jpeg.cpp $(UTIL)/jpeg.cpp \
		$(BIN)/libduetos_img_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(IMG_META_RUST)/include $^ -o $@

# PNG pulls the real util/gzip + util/deflate + util/crc32 +
# util/adler32 — the IDAT zlib stream is exercised for free.
$(BIN)/fuzz_png: fuzz_png.cpp $(UTIL)/png.cpp $(UTIL)/gzip.cpp \
		$(UTIL)/deflate.cpp $(UTIL)/adler32.cpp $(UTIL)/crc32.cpp \
		$(BIN)/libduetos_img_meta_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(IMG_META_RUST)/include $^ -o $@

# --- crypto DER / X.509 ------------------------------------------
#
# asn1::Read is a pure TLV walker; x509::Parse sits on top of it.
# The bytes are DER from a TLS handshake / on-disk cert.
$(BIN)/fuzz_asn1: fuzz_asn1.cpp $(CRYPTO)/asn1.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# x509.cpp pulls bigint/rsa (RsaPublicKeyFromBE on the parse path,
# BigIntToBytesBE in the in-TU self-test) — link both.
$(BIN)/fuzz_x509: fuzz_x509.cpp $(CRYPTO)/x509.cpp $(CRYPTO)/asn1.cpp \
		$(CRYPTO)/bigint.cpp $(CRYPTO)/rsa.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- firmware-package envelope -----------------------------------
#
# FwPackageParse validates a 160-byte header + SHA-256 payload
# digest; the real crypto/sha256 is linked so the digest gate is
# exercised (host_shim/util/result.h supplies Result).
$(BIN)/fuzz_fw_pkg: fuzz_fw_pkg.cpp $(LOADER)/firmware_package.cpp \
		$(CRYPTO)/sha256.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- PE export-directory walker ----------------------------------
#
# Distinct entry point from the PE loader (fuzz_pe): PeParseExports
# walks the EAT/ENT/EOT arrays directly on raw file bytes.
$(BIN)/fuzz_pe_exports: fuzz_pe_exports.cpp $(LOADER)/pe_exports.cpp \
		$(UTIL)/string.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- VT/ANSI terminal escape parser ------------------------------
#
# ParserFeed runs the DEC ANSI state machine over a PTY byte
# stream; util/unicode does the UTF-8 join.
# vt_parser.cpp delegates the DEC ANSI state machine to the
# `duetos_vt` Rust crate (kernel/util/vt_parser_rust/). Link the
# rlib + panic=abort staticlib pattern; a Rust-side panic in the
# state machine aborts as a libFuzzer crash.
VT_RUST := $(KERNEL)/util/vt_parser_rust

$(BIN)/libduetos_vt.rlib: $(VT_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_vt -O $< -o $@

$(BIN)/libduetos_vt_fuzz.a: host_shim/vt_fuzz_shim.rs \
		$(BIN)/libduetos_vt.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_vt=$(BIN)/libduetos_vt.rlib $< -o $@

$(BIN)/fuzz_vt: fuzz_vt.cpp $(UTIL)/vt_parser.cpp $(UTIL)/unicode.cpp \
		host_shim/vt_stubs.cpp $(BIN)/libduetos_vt_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(VT_RUST)/include $^ -o $@

# --- TLS 1.2 record + handshake parsers (Rust-backed) ------------
#
# net/tls.cpp delegates the five parser entry points
# (TlsPeekRecord, TlsPeekHandshake, TlsParseServerHello,
# TlsParseCertificateLeaf, TlsParseServerHelloDone) to the
# `duetos_tls` Rust crate. The fuzz harness must link the
# Rust staticlib via the same rlib + panic=abort staticlib
# recipe as the USB harnesses so the Rust crate's parser
# bodies are exercised on the fuzzed bytes. The state-machine
# half of tls.cpp still pulls in RSA + AES + x509 (TlsSelfTest
# body), so those object files stay on the link line.
NET           := $(KERNEL)/net
TLS_RUST      := $(KERNEL)/net/tls_rust

$(BIN)/libduetos_tls.rlib: $(TLS_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name duetos_tls -O $< -o $@

$(BIN)/libduetos_tls_fuzz.a: host_shim/tls_fuzz_shim.rs \
		$(BIN)/libduetos_tls.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern duetos_tls=$(BIN)/libduetos_tls.rlib $< -o $@

$(BIN)/fuzz_tls: fuzz_tls.cpp $(NET)/tls.cpp \
		$(CRYPTO)/hmac.cpp $(CRYPTO)/sha256.cpp $(CRYPTO)/sha1.cpp \
		$(CRYPTO)/bigint.cpp $(CRYPTO)/rsa.cpp $(CRYPTO)/aes.cpp \
		$(CRYPTO)/aes_gcm.cpp $(CRYPTO)/x509.cpp $(CRYPTO)/asn1.cpp \
		$(BIN)/libduetos_tls_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(TLS_RUST)/include $^ -o $@

# --- USB descriptors (Rust-backed) -------------------------------
#
# usb_class_desc.cpp + hid_descriptor.cpp delegate byte parsing
# to the `usbclass` + `usbhid` Rust crates. Same rlib +
# panic=abort staticlib recipe as duetos_exfat / duetos_ntfs:
# a Rust-side bounds/overflow bug in either walker aborts as a
# libFuzzer crash. host_shim/edid_stubs.cpp's ConsoleWrite
# no-ops are NOT pulled in here — the USB TUs use SerialWrite,
# which the host_shim/arch/x86_64/serial.h already inlines as
# a no-op.
USBCLASS_RUST := $(KERNEL)/drivers/usb/class_rust
USBHID_RUST   := $(KERNEL)/drivers/usb/hid_rust
USB           := $(KERNEL)/drivers/usb

$(BIN)/libusbclass.rlib: $(USBCLASS_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name usbclass -O $< -o $@

$(BIN)/libusbclass_fuzz.a: host_shim/usbclass_fuzz_shim.rs \
		$(BIN)/libusbclass.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern usbclass=$(BIN)/libusbclass.rlib $< -o $@

$(BIN)/fuzz_usbclass: fuzz_usbclass.cpp $(USB)/usb_class_desc.cpp \
		$(BIN)/libusbclass_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(USBCLASS_RUST)/include $^ -o $@

$(BIN)/libusbhid.rlib: $(USBHID_RUST)/src/lib.rs | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type rlib \
		--crate-name usbhid -O $< -o $@

$(BIN)/libusbhid_fuzz.a: host_shim/usbhid_fuzz_shim.rs \
		$(BIN)/libusbhid.rlib | $(BIN)
	$(RUSTC) --edition $(RUST_EDITION) -C panic=abort --crate-type staticlib \
		--extern usbhid=$(BIN)/libusbhid.rlib $< -o $@

$(BIN)/fuzz_usbhid: fuzz_usbhid.cpp $(USB)/hid_descriptor.cpp \
		host_shim/usbhid_stubs.cpp $(BIN)/libusbhid_fuzz.a | $(BIN)
	$(CXX) $(CXXFLAGS) -I $(USBHID_RUST)/include $^ -o $@

# --- EDID + CEA-861 EDID extension block -------------------------
#
# Both walkers are "pure compute, allocation-free, no IRQ" per
# their headers, so no shim TU is needed beyond host_shim/log/klog.
# CEA-861 includes edid.h transitively (shares the DTD struct),
# but only the structs — no kernel-side functions cross the
# boundary. The util/result.cpp dependency is shared with several
# other harnesses; the Makefile linker pulls it in via the kernel
# include path.
GPU := $(KERNEL)/drivers/gpu
# host_shim/edid_stubs.cpp resolves the kernel ConsoleWrite /
# ConsoleWriteln functions referenced by EdidDumpToConsole and
# Cea861DumpToConsole (shell-command path; never reached from
# the fuzz parser drive but pulled in by linking the full TU).
$(BIN)/fuzz_edid: fuzz_edid.cpp $(GPU)/edid.cpp host_shim/edid_stubs.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BIN)/fuzz_cea861: fuzz_cea861.cpp $(GPU)/cea861.cpp $(GPU)/edid.cpp host_shim/edid_stubs.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- x86_64 disassembler (crash-dump path) -----------------------
#
# DecodeStream runs on the crash-dump path so a decode bug there
# faults the post-mortem itself. The decoder is "allocation-free,
# IRQ-safe, panic-safe" per the header; host_shim/disasm_stubs.cpp
# resolves the two non-decode symbols disasm.cpp pulls in
# (FixJournalRecord — defensive self-healing observer; and the
# symbol-table resolver used by the operands formatter — always
# misses on host).
DEBUG := $(KERNEL)/debug
$(BIN)/fuzz_disasm: fuzz_disasm.cpp $(DEBUG)/disasm.cpp host_shim/disasm_stubs.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

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

run-ntfs: $(BIN)/fuzz_ntfs
	@mkdir -p corpus/ntfs
	@python3 seeds/gen_ntfs_seeds.py corpus/ntfs
	$(BIN)/fuzz_ntfs -max_len=262144 -max_total_time=60 -print_final_stats=1 corpus/ntfs

run-ext4: $(BIN)/fuzz_ext4
	@mkdir -p corpus/ext4
	@python3 seeds/gen_ext4_seeds.py corpus/ext4
	$(BIN)/fuzz_ext4 -max_len=1048576 -max_total_time=60 -print_final_stats=1 corpus/ext4

run-net: $(BIN)/fuzz_net
	@mkdir -p corpus/net
	@python3 seeds/gen_net_seeds.py corpus/net
	$(BIN)/fuzz_net -max_len=2048 -max_total_time=60 -print_final_stats=1 corpus/net

# Generic runner for the harnesses without a bespoke run-* above.
# Auto-seeds from seeds/gen_<name>_seeds.py when one exists (same
# rule fuzz-all.sh applies) so `make run-png` etc. starts past the
# format gate exactly like the explicit fs/exec targets do.
run-%: $(BIN)/fuzz_%
	@mkdir -p corpus/$*
	@[ -f seeds/gen_$*_seeds.py ] && python3 seeds/gen_$*_seeds.py corpus/$* || true
	$< -max_total_time=60 -print_final_stats=1 corpus/$*

# Throw everything at the OS at once: build every harness and run
# them all in parallel, aggregating crashes into one exit code.
# FUZZ_SECONDS / FUZZ_JOBS env vars tune the budget (see the
# script header). Non-zero exit iff any harness crashed — usable
# as a CI gate unmodified.
.PHONY: fuzz-all
fuzz-all:
	../../tools/test/fuzz-all.sh

clean:
	rm -rf $(BIN)
