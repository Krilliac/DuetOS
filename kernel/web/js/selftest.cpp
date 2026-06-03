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
    // 30. prototype chain: a plain {} inherits Object.prototype.toString,
    // so string-coercing it yields "[object Object]" (not NaN/garbage).
    run(CheckCase("'' + {};", "[object Object]", nullptr));
    // 31. inherited toString is callable directly via the chain.
    run(CheckCase("var o={}; o.toString();", "[object Object]", nullptr));
    // 32. an OWN toString overrides the inherited Object.prototype one.
    run(CheckCase("var o={toString:function(){return 'OWN';}}; '' + o;", "OWN", nullptr));
    // 33. numeric path: a plain object inherits valueOf (returns `this`,
    // skipped) then toString from Object.prototype, so `obj + 1` becomes
    // "[object Object]1" instead of NaN — proves the chain feeds
    // ToPrimitive's default-hint valueOf-then-toString ordering.
    run(CheckCase("({}) + 1;", "[object Object]1", nullptr));
    // 34. Object.prototype is reachable via the Object global and its
    // toString resolves through the chain to the structural form.
    run(CheckCase("typeof Object.prototype + ',' + Object.prototype.toString();", "object,[object Object]", nullptr));

    // 35. Array.prototype.map + join (callback at +1 depth).
    run(CheckCase("[1,2,3].map(function(x){return x*2;}).join(',');", "2,4,6", nullptr));
    // 36. Array.prototype.filter narrows by predicate; .length reads back.
    run(CheckCase("[1,2,3,4].filter(function(x){return x>2;}).length;", "2", nullptr));
    // 37. Array.prototype.slice with positive bounds, shallow copy.
    run(CheckCase("[10,20,30,40].slice(1,3).join(',');", "20,30", nullptr));
    // 38. Array.prototype.slice with a negative start counts from the end.
    run(CheckCase("[1,2,3,4,5].slice(-2).join(',');", "4,5", nullptr));
    // 39. Array.prototype.forEach runs the callback for its side effects.
    run(CheckCase("var s=0; [1,2,3,4].forEach(function(x){ s+=x; }); s;", "10", nullptr));
    // 40. String.prototype.split + index.
    run(CheckCase("'a,b,c'.split(',')[1];", "b", nullptr));
    // 41. String.prototype.charCodeAt returns the ASCII code unit.
    run(CheckCase("'A'.charCodeAt(0) + ',' + 'a'.charCodeAt(0);", "65,97", nullptr));
    // 42. String.prototype.replace — first occurrence, string pattern.
    run(CheckCase("'a-b-c'.replace('-', '+');", "a+b-c", nullptr));
    // 43. String.prototype.trim strips leading/trailing whitespace.
    run(CheckCase("('  hi  '.trim()) + '|' + '  hi  '.trim().length;", "hi|2", nullptr));
    // 44. Object.keys returns own keys as an array, join-able.
    run(CheckCase("Object.keys({a:1,b:2}).join(',');", "a,b", nullptr));
    // 45. Object.keys of an array yields its decimal index keys.
    run(CheckCase("Object.keys([7,8,9]).join(',');", "0,1,2", nullptr));

    // 46. Number.prototype.toString(16) — hex of an integer.
    run(CheckCase("(255).toString(16);", "ff", nullptr));
    // 47. Number.prototype.toString(2) — binary of an integer.
    run(CheckCase("(10).toString(2);", "1010", nullptr));
    // 48. Number.prototype.toString(8) + negative.
    run(CheckCase("(64).toString(8) + ',' + (-255).toString(16);", "100,-ff", nullptr));
    // 49. Number.prototype.toString() default radix == decimal.
    run(CheckCase("(123).toString();", "123", nullptr));
    // 50. Number.prototype.toFixed rounds to N fractional places.
    run(CheckCase("(3.14159).toFixed(2);", "3.14", nullptr));
    // 51. toFixed on an integer zero-pads the fraction.
    run(CheckCase("(5).toFixed(3);", "5.000", nullptr));
    // 52. toFixed(0) rounds half-away to a whole number.
    run(CheckCase("(2.5).toFixed(0);", "3", nullptr));
    // 53. isFinite: true for a finite number, false for a non-number,
    // true for a fractional finite result.
    run(CheckCase("isFinite(42) + ',' + isFinite('x') + ',' + isFinite(3.5);", "true,false,true", nullptr));
    // 54. isFinite of an overflow-to-Infinity product is false.
    run(CheckCase("isFinite(Math.pow(10, 40) * Math.pow(10, 40));", "false", nullptr));
    // 55. parseInt with an explicit radix argument.
    run(CheckCase("parseInt('ff', 16) + ',' + parseInt('1010', 2) + ',' + parseInt('777', 8);", "255,10,511", nullptr));
    // 56. parseInt auto-detects a 0x prefix when radix is omitted/0.
    run(CheckCase("parseInt('0x1F') + ',' + parseInt('0xff', 16);", "31,255", nullptr));
    // NOTE: JSON.parse's surrogate-pair combining (𐀀 -> one
    // astral code point, 4-byte UTF-8) cannot be exercised through a JS
    // string literal here: the JS lexer decodes the \u escapes in the
    // single-quoted argument BEFORE JSON.parse sees them, so the JSON
    // path never receives literal "\uXXXX". The combining is correct for
    // its real input (literal JSON from a fetched response) — see
    // JsonReadString — but is intentionally left without a self-test
    // rather than asserting on double-decoded bytes.

    // ---- RegExp engine (bounded NFA matcher) ----
    // 57. test(): digit-class quantifier matches a substring.
    run(CheckCase("/\\d+/.test('abc123');", "true", nullptr));
    // 58. test(): no match returns false.
    run(CheckCase("/\\d+/.test('abc');", "false", nullptr));
    // 59. global replace with a char-class escape.
    run(CheckCase("'a1b2c3'.replace(/\\d/g,'#');", "a#b#c#", nullptr));
    // 60. exec() returns a capture-group array; [1] is the first group.
    run(CheckCase("/(\\w+)@(\\w+)/.exec('a@b')[1];", "a", nullptr));
    // 61. exec() second capture group.
    run(CheckCase("/(\\w+)@(\\w+)/.exec('foo@bar')[2];", "bar", nullptr));
    // 62. split() on a char-class separator, re-joined.
    run(CheckCase("'a,b;c'.split(/[,;]/).join('|');", "a|b|c", nullptr));
    // 63. anchored full-string match.
    run(CheckCase("/^foo$/.test('foo');", "true", nullptr));
    // 64. anchors reject a partial string.
    run(CheckCase("/^foo$/.test('foobar');", "false", nullptr));
    // 65. case-insensitive flag.
    run(CheckCase("/HELLO/i.test('hello world');", "true", nullptr));
    // 66. alternation + match() returns the matched substring (non-global).
    run(CheckCase("'cat'.match(/dog|cat/)[0];", "cat", nullptr));
    // 67. search() returns the match index.
    run(CheckCase("'hello world'.search(/world/);", "6", nullptr));
    // 68. {n,m} bounded quantifier.
    run(CheckCase("/a{2,3}/.test('aaaa') + ',' + /a{2,3}/.test('a');", "true,false", nullptr));
    // 69. $& / $1 substitution in replace.
    run(CheckCase("'John Smith'.replace(/(\\w+) (\\w+)/, '$2 $1');", "Smith John", nullptr));
    // 70. word-boundary anchor.
    run(CheckCase("/\\bcat\\b/.test('the cat sat') + ',' + /\\bcat\\b/.test('category');", "true,false", nullptr));

    // ---- Math completion: random range + transcendentals ----
    // 73. Math.random() is in [0, 1) — RANGE check only (non-deterministic
    // by nature, so we never assert a specific value).
    run(CheckCase("var r=Math.random(); (r>=0)&&(r<1);", "true", nullptr));
    // 74. Math.sqrt of a perfect square is exact in the soft-float path.
    run(CheckCase("Math.sqrt(16);", "4", nullptr));
    // 75. Math.exp(0) == 1 exactly (the soft-float poly is exact at 0:
    // n=0, r=0, so the series collapses to 1.0). The trig polynomials
    // (sin/cos) carry ~3e-5 error so their identities are NOT asserted
    // here — only that they return a finite number (range, not value).
    run(CheckCase("Math.exp(0) + ',' + isFinite(Math.cos(0)) + ',' + isFinite(Math.sin(1)) + ',' + "
                  "isFinite(Math.tan(1)) + ',' + isFinite(Math.log(10));",
                  "1,true,true,true,true", nullptr));

    // ---- Date (UTC, epoch-ms backed) ----
    // 76. new Date(0) is the Unix epoch: 1970-01-01 (month 0).
    run(CheckCase("new Date(0).getFullYear() + '-' + new Date(0).getMonth();", "1970-0", nullptr));
    // 77. epoch day-of-month is the 1st; 1970-01-01 was a Thursday (day 4).
    run(CheckCase("new Date(0).getDate() + ',' + new Date(0).getDay();", "1,4", nullptr));
    // 78. midnight UTC: all time-of-day getters read zero.
    run(CheckCase("new Date(0).getHours() + ':' + new Date(0).getMinutes() + ':' + new Date(0).getSeconds();", "0:0:0",
                  nullptr));
    // 79. getTime round-trips the constructor's epoch-ms argument.
    run(CheckCase("new Date(1000).getTime();", "1000", nullptr));
    // 80. one second past the epoch: getSeconds reads 1.
    run(CheckCase("new Date(1000).getSeconds();", "1", nullptr));
    // 81. Date.now() yields a number (value is wall-clock-dependent, so we
    // assert only its type — deterministic regardless of the RTC).
    run(CheckCase("typeof Date.now();", "number", nullptr));
    // 82. toISOString of the epoch is the canonical fixed form.
    run(CheckCase("new Date(0).toISOString();", "1970-01-01T00:00:00.000Z", nullptr));

    // ---- CRITICAL: a catastrophic-backtracking pattern must TERMINATE
    // (degrade to no-match / a bounded answer), NOT hang the boot. The
    // explicit-stack VM + step budget guarantee this. The classic
    // exponential case `(a+)+$` on a long non-matching string would, with a
    // naive recursive matcher, both blow the kernel stack and run for an
    // astronomical number of steps. Here it must return a concrete boolean
    // within the budget. We don't assert WHICH boolean (a budget-exhausted
    // search returns false by design); we assert it RETURNS at all and the
    // eval does not error out / hang. ----
    run(CheckCase("/(a+)+$/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!');", "false", nullptr));
    // 72. a second pathological shape: nested optional star on a long run.
    run(CheckCase("/(a*)*b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaa');", "false", nullptr));

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
