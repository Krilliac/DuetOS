#!/usr/bin/env python3
"""Static contract check for the MSVC x64 C++ exception context path."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_xmm_unwind(source: str, label: str, helper: str) -> None:
    require("0x1A0" in source, f"{label}: canonical CONTEXT.Xmm0 offset missing")
    require(
        re.search(
            rf"op == 8.*?codes\[i \+ 1\] \* 16ULL.*?{helper}\(ContextRecord, \(int\)info,",
            source,
            re.DOTALL,
        )
        is not None,
        f"{label}: UWOP_SAVE_XMM128 must restore the scaled 16-byte slot",
    )
    require(
        re.search(
            rf"op == 9.*?\*\(const unsigned int\*\)&codes\[i \+ 1\].*?{helper}\(ContextRecord, \(int\)info,",
            source,
            re.DOTALL,
        )
        is not None,
        f"{label}: UWOP_SAVE_XMM128_FAR must restore the unscaled 32-bit slot",
    )


def require_hardened_unwinder(source: str, label: str, prefix: str, end_marker: str) -> None:
    start = source.index("__declspec(dllexport) void* RtlVirtualUnwind")
    end = source.index(end_marker, start)
    function = source[start:end]
    validate_call = f"!{prefix}_validate_unwind_chain(&view, rf)"
    require(validate_call in function, f"{label}: complete bounded unwind chain is not prevalidated")
    require(
        function.index(validate_call) < function.index("for (int "),
        f"{label}: validation must precede all CONTEXT mutation",
    )
    require("(void)ControlPc;" not in function, f"{label}: ControlPc is still discarded")
    require(
        f"{prefix}_prolog_offset(ui, ImageBase, rf, ControlPc)" in function,
        f"{label}: ControlPc-relative prologue offset is not computed",
    )
    skip = re.search(
        r"if \(code_offset > prolog_offset\)\s*\{\s*i \+= width;\s*continue;\s*\}",
        function,
    )
    require(skip is not None, f"{label}: not-yet-executed prologue operations are not width-skipped")
    width_check = f"!{prefix}_unwind_op_width(cw, frreg, &width) || width > count - i"
    require(width_check in function, f"{label}: continuation width is not checked during decoding")
    first_continuation_read = function.find("codes[i + 1]")
    require(
        first_continuation_read < 0 or function.index(width_check) < first_continuation_read,
        f"{label}: continuation slot is read before its width check",
    )
    require(
        "return (void*)0; /* prevalidation makes this unreachable */" in function
        or re.search(r"else\s*\{\s*return \(void\*\)0;\s*\}", function) is not None,
        f"{label}: unknown opcodes are not rejected deterministically",
    )
    for token in ("info > 1u", "info < 6u", "width > count - i"):
        require(token in source, f"{label}: validation contract missing {token}")


def main() -> int:
    asm = read("userland/libs/vcruntime140/cxx_throw.S")
    runtime = read("userland/libs/vcruntime140/vcruntime140.c")
    dispatch = read("userland/libs/ntdll/ntdll_dispatch.c")
    ntdll_seh = read("userland/libs/ntdll/ntdll_seh.c")
    kernel32 = read("userland/libs/kernel32/kernel32_interlocked.c")
    bounds = read("userland/libs/common/pe_unwind_bounds.h")
    bounds_test = read("tests/host/test_pe_unwind_bounds.cpp")
    build = read("tools/build/build-vcruntime140-dll.sh")
    kernel_cmake = read("kernel/CMakeLists.txt")
    host_cmake = read("tests/host/CMakeLists.txt")

    body_match = re.search(
        r"_CxxThrowException:\s*(.*?call\s+_CxxThrowExceptionImpl)",
        asm,
        re.DOTALL,
    )
    require(body_match is not None, "throw assembly wrapper/core call missing")
    body = body_match.group(1)
    require(".seh_proc _CxxThrowException" in asm, "throw wrapper lacks Windows unwind metadata")
    for token in (".seh_stackalloc 8", ".seh_stackalloc 0x4f8", ".seh_endprologue"):
        require(token in body, f"throw wrapper unwind description missing {token}")
    require(body.count(".seh_stackalloc 8") == 2, "RFLAGS/alignment pushes must be anonymous stack allocations")
    require(".seh_pushreg %r10" not in body, "volatile R10 must not be encoded as UWOP_PUSH_NONVOL")

    # RFLAGS must be sampled at the ABI entry, before SUB/XOR changes it.
    pushf = body.index("pushfq")
    first_flag_change = min(body.index("subq"), body.index("xorq"))
    require(pushf < first_flag_change, "caller RFLAGS must be captured before flag-changing instructions")
    require(
        re.search(r"movq\s+0x500\(%rsp\),\s*%rax.*?movl\s+%eax,\s*0x064\(%rsp\)", body, re.DOTALL)
        is not None,
        "saved entry RFLAGS are not copied to CONTEXT.EFlags",
    )

    # CONTEXT starts at rsp+0x20. Check every incoming GPR that is
    # saved directly before scratch use, plus synthesized caller RSP/RIP.
    gpr_stores = {
        "%rax": "0x098",
        "%rcx": "0x0a0",
        "%rdx": "0x0a8",
        "%rbx": "0x0b0",
        "%rbp": "0x0c0",
        "%rsi": "0x0c8",
        "%rdi": "0x0d0",
        "%r8": "0x0d8",
        "%r9": "0x0e0",
        "%r10": "0x0e8",
        "%r11": "0x0f0",
        "%r12": "0x0f8",
        "%r13": "0x100",
        "%r14": "0x108",
        "%r15": "0x110",
    }
    for register, offset in gpr_stores.items():
        require(
            re.search(rf"movq\s+{re.escape(register)},\s*{offset}\(%rsp\)", body) is not None,
            f"caller {register} is not captured at CONTEXT-relative {offset}",
        )
    require("leaq    0x510(%rsp), %rax" in body and "movq    %rax, 0x0b8(%rsp)" in body,
            "caller post-call RSP is not captured")
    require("movq    0x508(%rsp), %rax" in body and "movq    %rax, 0x118(%rsp)" in body,
            "caller return RIP is not captured")
    require("fxsave64 0x120(%rsp)" in body, "caller x87/MXCSR/XMM state is not captured")
    require(
        body.index("fxsave64 0x120(%rsp)") < body.index("call    _CxxThrowExceptionImpl"),
        "floating-point context must be captured before optimized C runs",
    )
    require("leaq    0x020(%rsp), %r8" in body, "aligned CONTEXT pointer is not passed as the third ABI argument")

    require(
        "_CxxThrowExceptionImpl(void* object, const void* throwInfo," in runtime
        and "unsigned char* caller_context)" in runtime,
        "C throw core must consume the assembly-captured CONTEXT pointer",
    )
    require("RtlCaptureContext" not in runtime, "optimized C must not recapture and clobber the caller context")
    require(
        "RtlLookupFunctionEntry((u64_)throwInfo, &image_base" in runtime,
        "C++ metadata image base must be derived from the ThrowInfo VA",
    )
    require(
        "caller_context + CXX_CONTEXT_RIP_OFF" in runtime,
        "ExceptionAddress must come from the captured caller CONTEXT",
    )
    require(
        "NtRaiseException(&rec, caller_context, 1" in runtime,
        "NtRaiseException must receive the complete caller CONTEXT",
    )
    require(
        "__declspec(dllexport) SEH_NORETURN void _CxxThrowException(" not in runtime,
        "C export would collide with the assembly ABI entry",
    )
    require("#define HT_IS_REFERENCE 0x08u" in runtime, "MSVC HandlerType reference flag is missing")
    require(
        re.search(
            r"if \(\(cb->adjectives & HT_IS_REFERENCE\) != 0\)\s*"
            r"\{\s*\*slot = thrown_obj;\s*\}\s*"
            r"else if \(cb->type_info != 0 && ct->size != 0 && ct->copy_ctor == 0\)",
            runtime,
        )
        is not None,
        "catch references must bind the thrown object while trivial by-value catches copy bytes",
    )
    require(
        "(ct->properties & 1) == 0" not in runtime,
        "CatchableType simple-type metadata must not select catch reference binding",
    )
    require(
        "if (!is_target_unwind)" in runtime
        and "RtlUnwindEx((void*)frame, (void*)0" in runtime
        and "disp->TargetIp = (u64_)cont;" in runtime,
        "C++ search must defer catch execution until target unwind and publish its continuation",
    )

    require("resume_rsp += 8" not in dispatch, "generic unwinder still contains a throw-helper stack workaround")
    require(
        "if (is_target)\n                TargetIp = (void*)dc.TargetIp;" in dispatch,
        "RtlUnwindEx must honor a target personality's continuation",
    )
    require(
        "dc.ContextRecord = c;" in dispatch
        and "lang(ExceptionRecord, (void*)establisher, c, &dc);" in dispatch,
        "unwind handlers must receive the current unwound CONTEXT",
    )
    require(
        re.search(r"for \(unsigned i = 0; i < 1232; \+\+i\)\s*r\[i\] = c\[i\];", dispatch) is not None,
        "RtlUnwindEx must copy the fully unwound CONTEXT wholesale",
    )
    require(
        "r[i] = ((unsigned char*)ContextRecord)[i];" not in dispatch,
        "RtlUnwindEx must not resume from the original exception registers",
    )
    require_xmm_unwind(ntdll_seh, "ntdll", "nt_restore_xmm")
    require_xmm_unwind(kernel32, "kernel32", "k32_restore_xmm")
    require_hardened_unwinder(ntdll_seh, "ntdll", "nt", "/* RtlCaptureContext lives")
    require_hardened_unwinder(kernel32, "kernel32", "k32", "/* Real RtlCaptureStackBackTrace")

    require("static unsigned char read_unwind_handler" not in dispatch,
            "dispatcher still carries an unchecked duplicate UNWIND_INFO parser")
    require(
        dispatch.count("RtlpReadUnwindHandler(ib, pc, fe,") == 2,
        "search and unwind passes must use the shared ControlPc-aware handler lookup",
    )
    handler_start = ntdll_seh.index("unsigned char RtlpReadUnwindHandler")
    handler_end = ntdll_seh.index("/* Real x64 table-based RtlVirtualUnwind", handler_start)
    handler_lookup = ntdll_seh[handler_start:handler_end]
    for token in (
        "ControlPc - ImageBase >= view.size",
        "nt_validate_unwind_chain(&view, first)",
        "nt_chain_frame_established(&view, first, ImageBase, ControlPc)",
        "duet_pe_rva_executable(&view, handler_rva)",
    ):
        require(token in handler_lookup, f"validated handler lookup missing {token}")
    require(
        handler_lookup.index("duet_pe_rva_executable(&view, handler_rva)")
        < handler_lookup.index("*Handler = (void*)(ImageBase + handler_rva)"),
        "handler RVA must be executable and in-bounds before pointer formation",
    )

    for token in (
        "DUET_PE_HEADER_PROBE",
        "e_lfanew",
        "optional_size",
        "image_size",
        "headers_size",
        "pdata_rva",
        "pdata_size",
        "duet_pe_runtime_function_pointer",
        "duet_pe_unwind_layout",
        "duet_pe_span_mapped",
        "duet_pe_validate_unwind_chain",
        "duet_pe_chain_frame_established",
        "tail_bytes",
        "duet_pe_rva_executable",
    ):
        require(token in bounds, f"PE bounds layer missing {token}")
    require(
        "duet_pe_range(e_lfanew, 24u, DUET_PE_HEADER_PROBE)" in bounds
        and "duet_pe_range(pdata_rva, pdata_size, image_size)" in bounds
        and "duet_pe_span_mapped(out, pdata_rva, pdata_size)" in bounds
        and "duet_pe_span_mapped(view, unwind_rva, tail_rva - unwind_rva + tail_bytes)" in bounds,
        "PE header, mapped pdata, and mapped aligned unwind-tail bounds are not all enforced",
    )
    for mirror, label in ((ntdll_seh, "ntdll"), (kernel32, "kernel32")):
        require('#include "../common/pe_unwind_bounds.h"' in mirror, f"{label}: shared PE bounds include missing")
        require(
            mirror.count("duet_pe_parse((const void*)") >= 2,
            f"{label}: lookup and virtual unwind must both derive validated SizeOfImage",
        )

    for token in (
        "0xFF0",
        "section table leaves first mapped page",
        "partial RUNTIME_FUNCTION",
        "pdata points into an unmapped image gap",
        "function end past SizeOfImage",
        "overlapping runtime-function ranges",
        "section range crosses SizeOfImage",
        "UNWIND_INFO header straddles image end",
        "UNWIND_INFO points into an unmapped image gap",
        "CHAININFO | EHANDLER",
        "handler tail exceeds image",
        "tail crosses into mapped gap",
        "Secondary: no SET_FPREG",
        "secondary SAVE_NONVOL",
        "SAVE not executed yet",
        "primary froff differs from secondary",
        "zero characteristics fail closed",
        "non-executable fails closed",
    ):
        require(token in bounds_test, f"synthetic malformed/boundary coverage missing {token}")
    require(
        "add_host_test(pe_unwind_bounds)" in host_cmake,
        "synthetic PE unwind bounds test is not registered in the host gate",
    )

    aligned_context = re.compile(
        r"unsigned char \w+\[1232\] __attribute__\(\(aligned\(16\)\)\);"
    )
    require(
        len(aligned_context.findall(dispatch)) == 4,
        "all four ntdll dispatch CONTEXT buffers must be explicitly 16-byte aligned",
    )
    require(
        len(aligned_context.findall(ntdll_seh)) == 1,
        "ntdll capture/backtrace CONTEXT buffer must be explicitly 16-byte aligned",
    )
    require(
        len(aligned_context.findall(kernel32)) == 1,
        "kernel32 capture/backtrace CONTEXT buffer must be explicitly 16-byte aligned",
    )

    for token in ("SRC_S_CXX_THROW", "OBJ_S_CXX_THROW", '"${SRC_S_CXX_THROW}"', '"${OBJ_S_CXX_THROW}"'):
        require(token in build, f"vcruntime build wiring missing {token}")
    require(
        '"${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/cxx_throw.S"' in kernel_cmake,
        "CMake incremental dependency missing cxx_throw.S",
    )
    require(
        kernel_cmake.count('"${CMAKE_SOURCE_DIR}/userland/libs/common/pe_unwind_bounds.h"') == 2,
        "kernel32 and ntdll embed rules must both depend on the PE bounds header",
    )
    require(
        "NAME cxxeh_context_contract" in host_cmake
        and "tools/test/cxxeh-context-contract.py" in host_cmake,
        "C++ EH context contract is not registered in the host CTest gate",
    )

    print("[cxxeh-context-contract] PASS (aligned context + bounded PE/handler + prologue-aware GPR/XMM unwind)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, UnicodeError, ValueError) as exc:
        print(f"[cxxeh-context-contract] FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
