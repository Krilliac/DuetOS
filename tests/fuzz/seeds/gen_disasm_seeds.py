#!/usr/bin/env python3
# DuetOS disassembler fuzz seed generator.
#
# WHAT  Emits raw x86_64 instruction byte streams so fuzz_disasm
#       (kernel/debug/disasm.cpp::DecodeStream) starts past the
#       "first byte decides what opcode shape we're in" gate and
#       exercises the actual operand walkers + relative-branch
#       formatter. Each seed targets one or more opcode families
#       the in-house decoder claims to handle:
#         - prologue.bin: function prologue (push rbp; mov rbp,
#           rsp; sub rsp, imm) — exercises ModRM + imm8/imm32
#         - alu.bin: ADD/SUB/XOR over REX/no-REX, reg/reg and
#           reg/imm — exercises the ALU table walker
#         - control.bin: CALL rel32 + Jcc rel8 + Jcc rel32 + RET
#           — exercises the relative-branch absolute-target
#           formatter that uses `va` from the harness
#         - simd.bin: MOV{UP,AP,DQ}, MOVSS, ADDPS, XORPS —
#           exercises the prefix-selected SIMD subset
#         - unknown.bin: bytes that the decoder MUST treat as `db`
#           rows (VEX 0xC4, EVEX 0x62, x87 0xD8) — exercises the
#           ClassifyRejectedByte path
#
# WHY   Without seeds the fuzzer wastes most of its budget on
#       bytes that bounce off random REX prefixes / 2-byte opcode
#       maps before ever reaching the operand walkers. The seeds
#       are short (10-40 bytes each) — libFuzzer's coverage-guided
#       mutator splits coverage across all five paths quickly from
#       this start.
#
# USAGE  python3 gen_disasm_seeds.py <out_dir>

import os
import sys


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/disasm"
    os.makedirs(out, exist_ok=True)

    # Function prologue: push rbp; mov rbp, rsp; sub rsp, 0x20;
    # mov eax, 0; pop rbp; ret.
    open(os.path.join(out, "prologue.bin"), "wb").write(bytes([
        0x55,                                # push rbp
        0x48, 0x89, 0xE5,                    # mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,              # sub rsp, 0x20
        0xB8, 0x00, 0x00, 0x00, 0x00,        # mov eax, 0
        0x5D,                                # pop rbp
        0xC3,                                # ret
    ]))

    # ALU mix: add rax, rbx; sub eax, 1; xor r8, r9; or al, 0x42;
    # cmp rcx, rdx.
    open(os.path.join(out, "alu.bin"), "wb").write(bytes([
        0x48, 0x01, 0xD8,        # add rax, rbx
        0x83, 0xE8, 0x01,        # sub eax, 1
        0x4D, 0x31, 0xC8,        # xor r8, r9
        0x0C, 0x42,              # or al, 0x42
        0x48, 0x39, 0xD1,        # cmp rcx, rdx
    ]))

    # Control flow: call rel32; je rel8; jne rel32; ret. The
    # relative branch operand uses va=0xffffffff80100000 from the
    # harness — formatter must compute target = va + insn_len +
    # rel.
    open(os.path.join(out, "control.bin"), "wb").write(bytes([
        0xE8, 0x10, 0x00, 0x00, 0x00,        # call +0x10
        0x74, 0x05,                          # je +5
        0x0F, 0x85, 0x00, 0x01, 0x00, 0x00,  # jne +0x100
        0xC3,                                # ret
    ]))

    # SIMD: movups xmm0, xmm1; movss xmm0, [rcx]; addps xmm0,
    # xmm2; xorps xmm0, xmm0.
    open(os.path.join(out, "simd.bin"), "wb").write(bytes([
        0x0F, 0x10, 0xC1,                    # movups xmm0, xmm1
        0xF3, 0x0F, 0x10, 0x01,              # movss xmm0, [rcx]
        0x0F, 0x58, 0xC2,                    # addps xmm0, xmm2
        0x0F, 0x57, 0xC0,                    # xorps xmm0, xmm0
    ]))

    # Bytes the decoder must reject as `db`: VEX 2-byte prefix,
    # EVEX 4-byte prefix, x87 escape. Each consumed as a 1-byte
    # `db` row with a category hint.
    open(os.path.join(out, "unknown.bin"), "wb").write(bytes([
        0xC4, 0xE1, 0x78, 0x10,              # vmovups (VEX) — rejected
        0x62, 0xF1, 0x7C, 0x48, 0x10, 0xC1,  # vmovups (EVEX) — rejected
        0xD8, 0xC1,                          # fadd st0, st1 (x87) — rejected
    ]))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
