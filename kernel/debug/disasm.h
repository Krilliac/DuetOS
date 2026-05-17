#pragma once

#include "util/types.h"

/*
 * DuetOS — in-house x86_64 disassembler.
 *
 * Scope: a textual single-instruction decoder built for the
 * native debugger's Disasm tab and the `dbg dis` shell command.
 * Goal is "readable mnemonics for the common subset, honest
 * `db 0xXX` rows for everything else." Not a substitute for
 * Capstone / Zydis — those become a follow-up if the rejected-
 * byte rate climbs in real workloads.
 *
 * Coverage (long mode, REX-aware):
 *   - MOV (reg/reg, reg/mem, mem/reg, reg/imm, mem/imm)
 *   - LEA
 *   - PUSH / POP (reg, mem)
 *   - ALU: ADD / OR / ADC / SBB / AND / SUB / XOR / CMP / TEST
 *   - INC / DEC / NEG / NOT
 *   - CALL (near, rel32; reg/mem indirect)
 *   - JMP (rel8, rel32; reg/mem indirect)
 *   - Jcc (all 16 condition codes, rel8 + rel32)
 *   - RET (near, near + imm16)
 *   - INT3, INT imm8
 *   - SYSCALL, SYSRET
 *   - NOP (single-byte + multi-byte 0F 1F variants)
 *   - HLT, CLI, STI, CLD, STD, IRETQ, LEAVE
 *   - SSE/SSE2 two-XMM-operand subset: MOV{UP,AP,DQ}{S,D} /
 *     MOV{SS,SD}, the scalar+packed arith family (ADD/SUB/MUL/
 *     DIV/MIN/MAX/SQRT/CVT, prefix-selected ss/sd/ps/pd),
 *     U/COMIS{S,D}, AND/ANDN/OR/XORP{S,D}, P{XOR,AND,ANDN,OR},
 *     UNPCKL/H P{S,D}
 *   - SSE XMM<->GPR forms: MOVD/MOVQ, CVTSI2SS/SD,
 *     CVT(T)SS2SI/SD2SI, MOVNTI
 *   - MOV{L,H}PS / MOV{L,H}PD / MOVLHPS / MOVHLPS
 *
 * Bytes outside the covered set decode as `db 0xXX` with the
 * `inspect::ClassifyByte` hint stitched into the operands field
 * so the operator still gets a one-word category (jump, simd,
 * prefix, ...). Instruction boundaries are correct for the
 * covered set; for `db` rows we conservatively consume one byte.
 *
 * Out of scope (deliberate, marked `// GAP:` at sites):
 *   - The integer-SIMD PUNPCK/PSHUF/PADD/PCMP/PMOVMSKB family,
 *     the SSE3 dup moves (MOVDDUP / MOVS[LH]DUP), x87,
 *     AVX/VEX/EVEX
 *   - The full string-op family (REP MOVS / SCAS / CMPS)
 *   - Far calls / jumps, segment-prefix-modulated mem operands
 *   - Privileged op decoding beyond what the kernel itself uses
 *
 * Context: kernel. Allocation-free, IRQ-safe, panic-safe — uses
 * only static buffers passed in by the caller. No syscalls, no
 * spinlocks, no dynamic dispatch.
 */

namespace duetos::debug::disasm
{

/// Cap on the bytes any single instruction may consume. Real
/// x86_64 maxes at 15 — we use 16 for headroom and so SIMD
/// `db` rows can still report a sensible `len` if asked.
inline constexpr u8 kMaxInsnLen = 15;

/// Per-row output. All strings are NUL-terminated. The buffers
/// are sized for the worst case the covered set produces:
///   bytes_text  — up to 15 bytes × "XX " = 45 + NUL
///   mnemonic    — longest covered mnemonic is "movsxd" (6)
///   operands    — `mov rax, [rbp+0x12345678]` ≈ 32; round up.
struct DecodedInsn
{
    u64 addr;            // VA of the first byte of this insn
    u8 len;              // bytes consumed (1..kMaxInsnLen)
    bool decoded;        // false → mnemonic == "db", operands has hint
    char bytes_text[48]; // hex-pair list, space-separated, NUL-terminated
    char mnemonic[12];
    char operands[64];
};

/// Decode one instruction starting at `bytes`. `available` caps how
/// many bytes the decoder is allowed to read (when fewer than 15
/// bytes of legitimate input remain — e.g. end of a copied window).
/// `va` is stamped into `out->addr` and used to compute relative-
/// branch absolute targets in the operands field. Returns the byte
/// count consumed (always 1..kMaxInsnLen, never 0 — an unknown
/// opcode produces a 1-byte `db` row so the caller can keep walking
/// the stream without getting stuck).
u8 DecodeOne(const u8* bytes, u64 available, u64 va, DecodedInsn* out);

/// Decode `available` bytes worth of instructions, filling up to
/// `row_cap` rows. Returns the number of rows written. Stops at
/// the first row whose insn would extend past `available` (ragged
/// tail rows are not emitted — caller can re-call from there with
/// more bytes).
u64 DecodeStream(const u8* bytes, u64 available, u64 va, DecodedInsn* out, u64 row_cap);

/// Boot-time self-test. Decodes a fixed `static constexpr u8`
/// fixture covering one row of each opcode family the decoder
/// claims to handle, plus one VEX byte the decoder MUST reject as
/// `db`. Compares each row's `(len, mnemonic, operands)` against a
/// hardcoded expected list. Returns true on success. Emits one
/// structural log line (`[smoke] disasm=ok rows=N` on success,
/// `[smoke] disasm=FAIL row=N got="..." expected="..."` on miss)
/// so CI can grep without the rest of klog noise.
bool SelfTest();

} // namespace duetos::debug::disasm
