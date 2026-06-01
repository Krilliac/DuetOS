#include "web/js/engine.h"

#include "web/js/arena.h"
#include "web/js/ast.h"
#include "web/js/builtins.h"
#include "web/js/interp.h"
#include "web/js/lexer.h"
#include "web/js/object.h"

/*
 * DuetOS — kernel/web/js: public eval entry point.
 *
 * Pipeline: Lex -> Parse -> InstallBuiltins -> walk Program. The whole
 * pipeline runs off a single bump arena so there is nothing to free.
 * The step budget bounds runtime; the call-depth cap bounds the native
 * stack; the arena cap bounds memory. A hostile script cannot hang or
 * exhaust the kernel.
 */

namespace duetos::web::js
{

using namespace duetos::core;

// Static fallback arena for boot/self-test callers that don't bring
// their own buffer. Single-threaded use only (boot path / self-test).
// Sized for the self-test battery with comfortable headroom.
namespace
{
alignas(16) u8 g_staticArena[kDefaultArenaBytes];
}

Result<void> JsEval(const char* src, u32 len, JsValue* out, char* console_out, u32 console_cap, const EvalConfig& cfg,
                    u8* scratch, u64 scratchLen)
{
    u8* base = scratch ? scratch : g_staticArena;
    u64 cap = scratch ? scratchLen : sizeof(g_staticArena);
    Arena arena(base, cap);

    if (console_out && console_cap)
        console_out[0] = '\0';

    TokenStream toks = Lex(src, len, arena);
    if (!toks.ok)
        return Err{ErrorCode::InvalidArgument};

    ParseResult pr = Parse(toks, arena);
    if (!pr.ok)
        return Err{ErrorCode::InvalidArgument};

    ConsoleBuf console{console_out, console_cap, 0};
    Interp I(arena, console);
    I.stepBudget = cfg.stepBudget;
    I.maxDepth = cfg.maxDepth;
    I.depth = 0;
    I.flow = Flow::Normal;
    I.returnValue = JsValue::Undefined();

    I.global = EnvNew(arena, nullptr);
    if (!I.global)
        return Err{ErrorCode::OutOfMemory};

    RESULT_TRY(InstallBuiltins(I));

    Result<JsValue> r = EvalStmt(I, pr.program, I.global);

    // Always NUL-terminate the captured console buffer.
    if (console_out && console_cap)
        console_out[console.len < console_cap ? console.len : console_cap - 1] = '\0';

    if (!r)
        return Err{r.error()};

    if (out)
        *out = r.value();
    return {};
}

Result<void> JsEvalToString(const char* src, u32 len, char* result_out, u32 result_cap, char* console_out,
                            u32 console_cap, const EvalConfig& cfg)
{
    JsValue v = JsValue::Undefined();
    RESULT_TRY(JsEval(src, len, &v, console_out, console_cap, cfg));
    if (result_out && result_cap)
    {
        u32 n = ValueToChars(v, result_out, result_cap - 1);
        result_out[n] = '\0';
    }
    return {};
}

} // namespace duetos::web::js
