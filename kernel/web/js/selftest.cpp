#include "web/js/engine.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

/*
 * DuetOS — kernel/web/js: boot self-test battery.
 *
 * Evaluates a curated set of snippets and asserts each against either
 * its completion value's string form or the captured console output.
 * Emits one structural sentinel line on success:
 *     [js-selftest] PASS (N/N snippets)
 * On any failure fires KBP_PROBE_V(kBootSelftestFail, idx) and emits a
 * FAIL line naming the failing snippet index.
 *
 * The final case proves the step budget aborts an infinite loop with
 * an error instead of hanging — CRITICAL for not wedging the boot.
 */

namespace duetos::web::js
{

namespace
{

bool StrEqZ(const char* a, const char* b)
{
    return duetos::core::StrEqual(a, b);
}

// Format an unsigned count as decimal into `out`; returns chars.
u32 WriteDec(u32 v, char* out)
{
    char tmp[12];
    u32 t = 0;
    if (v == 0)
        tmp[t++] = '0';
    while (v)
    {
        tmp[t++] = char('0' + (v % 10));
        v /= 10;
    }
    u32 o = 0;
    while (t)
        out[o++] = tmp[--t];
    out[o] = '\0';
    return o;
}

// Run `src`, expect the completion-value string == `expectVal` (if
// non-null) AND the console output == `expectConsole` (if non-null).
bool CheckCase(const char* src, const char* expectVal, const char* expectConsole)
{
    char resultBuf[256];
    char consoleBuf[512];
    EvalConfig cfg;
    Result<void> r = JsEvalToString(src, duetos::core::StrLen(src), resultBuf, sizeof(resultBuf), consoleBuf,
                                    sizeof(consoleBuf), cfg);
    if (!r)
    {
        ::duetos::arch::SerialWrite("[js-dbg] eval-err src=<");
        ::duetos::arch::SerialWrite(src);
        ::duetos::arch::SerialWrite("> code=");
        ::duetos::arch::SerialWriteHex(u64(r.error()));
        ::duetos::arch::SerialWrite("\n");
        return false;
    }
    if (expectVal && !StrEqZ(resultBuf, expectVal))
    {
        ::duetos::arch::SerialWrite("[js-dbg] val src=<");
        ::duetos::arch::SerialWrite(src);
        ::duetos::arch::SerialWrite("> got=<");
        ::duetos::arch::SerialWrite(resultBuf);
        ::duetos::arch::SerialWrite("> want=<");
        ::duetos::arch::SerialWrite(expectVal);
        ::duetos::arch::SerialWrite(">\n");
        return false;
    }
    if (expectConsole && !StrEqZ(consoleBuf, expectConsole))
    {
        ::duetos::arch::SerialWrite("[js-dbg] con src=<");
        ::duetos::arch::SerialWrite(src);
        ::duetos::arch::SerialWrite("> got=<");
        ::duetos::arch::SerialWrite(consoleBuf);
        ::duetos::arch::SerialWrite(">\n");
        return false;
    }
    return true;
}

// Expect the eval to FAIL with a specific error code (used for the
// runaway-loop / depth cases).
bool CheckErr(const char* src, ErrorCode want, const EvalConfig& cfg)
{
    JsValue v = JsValue::Undefined();
    char consoleBuf[64];
    Result<void> r = JsEval(src, duetos::core::StrLen(src), &v, consoleBuf, sizeof(consoleBuf), cfg);
    bool ok = !r && r.error() == want;
    if (!ok)
    {
        ::duetos::arch::SerialWrite("[js-dbg] err src=<");
        ::duetos::arch::SerialWrite(src);
        ::duetos::arch::SerialWrite("> hasVal=");
        ::duetos::arch::SerialWriteHex(u64(r.has_value()));
        ::duetos::arch::SerialWrite(" code=");
        ::duetos::arch::SerialWriteHex(u64(r.error()));
        ::duetos::arch::SerialWrite(" want=");
        ::duetos::arch::SerialWriteHex(u64(want));
        ::duetos::arch::SerialWrite("\n");
    }
    return ok;
}

} // namespace

void JsSelfTest()
{
    int total = 0;
    int failIdx = -1;

    auto run = [&](bool ok)
    {
        if (failIdx < 0 && !ok)
            failIdx = total;
        ++total;
    };

    // 1. arithmetic + precedence: 2 + 3 * 4 == 14
    run(CheckCase("2 + 3 * 4;", "14", nullptr));
    // 2. parentheses override precedence: (2 + 3) * 4 == 20
    run(CheckCase("(2 + 3) * 4;", "20", nullptr));
    // 3. closure counter: returns 3 after three increments
    run(CheckCase("function mk(){var c=0; return function(){c+=1; return c;};} "
                  "var f=mk(); f(); f(); f();",
                  "3", nullptr));
    // 4. recursion: factorial(5) == 120
    run(CheckCase("function fact(n){ if(n<=1) return 1; return n*fact(n-1); } fact(5);", "120", nullptr));
    // 5. for-loop sum 1..100 == 5050
    run(CheckCase("var s=0; for(var i=1;i<=100;i+=1){ s+=i; } s;", "5050", nullptr));
    // 6. string methods: "hello".toUpperCase().slice(0,3) == "HEL"
    run(CheckCase("'hello'.toUpperCase().slice(0,3);", "HEL", nullptr));
    // 7. string indexOf
    run(CheckCase("'duetos kernel'.indexOf('kernel');", "7", nullptr));
    // 8. array map + filter + join
    run(CheckCase("[1,2,3,4].map(function(x){return x*x;}).filter(function(x){return x>4;}).join(',');", "9,16",
                  nullptr));
    // 9. array push/pop/length
    run(CheckCase("var a=[1,2]; a.push(3); a.push(4); a.pop(); a.length + ':' + a.join('-');", "3:1-2-3", nullptr));
    // 10. object property access
    run(CheckCase("var o={name:'duet', n:42}; o.name + '=' + o['n'];", "duet=42", nullptr));
    // 11. ternary + logical short-circuit
    run(CheckCase("var x = (1 < 2) ? 'yes' : 'no'; var y = false && undefinedThing; x + ',' + (y===false);", "yes,true",
                  nullptr));
    // 12. logical OR returns first truthy
    run(CheckCase("0 || '' || 'fallback';", "fallback", nullptr));
    // 13. typeof spectrum
    run(CheckCase("typeof 1 + ',' + typeof 'a' + ',' + typeof true + ',' + typeof undefinedX + ',' + typeof null;",
                  "number,string,boolean,undefined,object", nullptr));
    // 14. === vs == : '5'==5 true, '5'===5 false
    run(CheckCase("('5' == 5) + ',' + ('5' === 5) + ',' + (null == undefined) + ',' + (null === undefined);",
                  "true,false,true,false", nullptr));
    // 15. console.log capture
    run(CheckCase("console.log('hello', 'world'); console.log(1+2);", nullptr, "hello world\n3\n"));
    // 16. arrow function + Math
    run(CheckCase("var sq = x => x*x; Math.max(sq(3), Math.sqrt(16), Math.abs(-7));", "9", nullptr));
    // 17. while loop with break/continue
    run(CheckCase("var s=0; var i=0; while(true){ i+=1; if(i>10) break; if(i%2===0) continue; s+=i; } s;", "25",
                  nullptr));
    // 18. parseInt / parseFloat / isNaN
    run(CheckCase("parseInt('42px') + ',' + isNaN(parseInt('abc')) + ',' + (parseFloat('3.5') > 3);", "42,true,true",
                  nullptr));
    // 19. nested closures capturing loop-free state
    run(CheckCase("function adder(a){ return function(b){ return a+b; }; } adder(10)(32);", "42", nullptr));
    // 20. JSON.stringify of a flat object/array
    run(CheckCase("JSON.stringify([1,'two',true,null]);", "[1,\"two\",true,null]", nullptr));
    // 21. JSON.parse round-trips a nested object/array and re-stringifies
    run(CheckCase("JSON.stringify(JSON.parse('{\"a\":[1,2,3],\"b\":\"x\"}'));", "{\"a\":[1,2,3],\"b\":\"x\"}",
                  nullptr));
    // 22. JSON.parse field access (number, string, array element)
    run(CheckCase("var o=JSON.parse('{\"n\":42,\"s\":\"hi\",\"arr\":[7,8]}'); o.n + ',' + o.s + ',' + o.arr[1];",
                  "42,hi,8", nullptr));
    // 23. JSON.parse of malformed input yields undefined (no throw)
    run(CheckCase("typeof JSON.parse('{bad json');", "undefined", nullptr));
    // 24. template literal with an interpolated expression
    run(CheckCase("`a${1+2}b`;", "a3b", nullptr));
    // 25. template literal: multiple interpolations + identifiers
    run(CheckCase("var name='duet'; var v=3; `hi ${name} v${v}!`;", "hi duet v3!", nullptr));
    // 26. nested ${ } with an object literal inside the interpolation
    run(CheckCase("`x=${ {n:5}.n + 1 }`;", "x=6", nullptr));
    // 27. object-to-primitive: valueOf() drives numeric coercion
    run(CheckCase("var o={valueOf:function(){return 5;}}; (o + 1) + ',' + (o + 1 === 6);", "6,true", nullptr));
    // 28. object-to-primitive: toString() drives string coercion
    run(CheckCase("var o={toString:function(){return 'OBJ';}}; `<${o}>`;", "<OBJ>", nullptr));
    // 29. loose-equals coerces an object via valueOf
    run(CheckCase("var o={valueOf:function(){return 7;}}; (o == 7) + ',' + (o == 8);", "true,false", nullptr));

    // ---- CRITICAL: runaway loop must be killed by the step budget,
    // not hang the boot. Use a tiny budget so it returns fast. ----
    {
        EvalConfig tight;
        tight.stepBudget = 100000;
        run(CheckErr("while(true){}", ErrorCode::Timeout, tight));
    }
    // 22. runaway recursion must hit the depth cap (Overflow), not smash
    // the native stack. This self-test runs on the boot thread's large
    // (non-arena) stack, where the kstack-arena native-stack guard does
    // NOT apply, so the LOGICAL maxDepth is the only backstop — keep it
    // low enough that maxDepth native frames (~15 KiB each in debug) stay
    // within the boot stack. On an arena-stacked thread (e.g. the browser
    // fetch worker) the native guard in CallFunction fires first.
    {
        EvalConfig cfg;
        cfg.maxDepth = 4;
        run(CheckErr("function rec(){ return rec(); } rec();", ErrorCode::Overflow, cfg));
    }
    // 23. syntax error surfaces InvalidArgument, not a crash.
    {
        EvalConfig cfg;
        run(CheckErr("var = ;", ErrorCode::InvalidArgument, cfg));
    }

    char numBuf[12];

    if (failIdx >= 0)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, u64(failIdx));
        ::duetos::arch::SerialWrite("[js-selftest] FAIL (snippet ");
        WriteDec(u32(failIdx), numBuf);
        ::duetos::arch::SerialWrite(numBuf);
        ::duetos::arch::SerialWrite(")\n");
        return;
    }

    ::duetos::arch::SerialWrite("[js-selftest] PASS (");
    WriteDec(u32(total), numBuf);
    ::duetos::arch::SerialWrite(numBuf);
    ::duetos::arch::SerialWrite("/");
    ::duetos::arch::SerialWrite(numBuf);
    ::duetos::arch::SerialWrite(" snippets)\n");
}

} // namespace duetos::web::js
