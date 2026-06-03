#include "web/js/interp.h"

#include "mm/frame_allocator.h"
#include "mm/kstack.h"
#include "util/string.h"
#include "web/js/builtins.h"
#include "web/js/engine.h"

/*
 * DuetOS — kernel/web/js: the tree-walking interpreter.
 *
 * EvalExpr / EvalStmt recursively walk the AST. Completion signals
 * (break/continue/return) propagate via Interp::flow rather than C++
 * exceptions (kernel is -fno-exceptions). Every node ticks the step
 * budget; a runaway loop exhausts it and surfaces ErrorCode::Timeout.
 */

namespace duetos::web::js
{

using namespace duetos::core;


// ----------------------- member access -----------------------

Result<JsValue> GetMember(Interp& I, const JsValue& obj, const char* key, u32 keyLen)
{
    return GetMemberImpl(I, obj, key, keyLen);
}

// ----------------------- expression eval -----------------------

static Result<JsValue> EvalArrayLit(Interp& I, const AstNode* n, Env* env)
{
    JsObject* arr = ObjNew(I.arena, true);
    if (!arr)
        return Err{ErrorCode::OutOfMemory};
    for (u32 i = 0; i < n->kidCount; ++i)
    {
        JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->kids[i], env));
        if (!ArrPush(arr, I.arena, v))
            return Err{ErrorCode::OutOfMemory};
    }
    return JsValue::Obj(arr);
}

static Result<JsValue> EvalObjectLit(Interp& I, const AstNode* n, Env* env)
{
    JsObject* obj = ObjNew(I.arena, false);
    if (!obj)
        return Err{ErrorCode::OutOfMemory};
    for (u32 i = 0; i < n->kidCount; ++i)
    {
        JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->kids[i], env));
        if (!ObjSet(obj, I.arena, n->keys[i], n->keyLens[i], v))
            return Err{ErrorCode::OutOfMemory};
    }
    return JsValue::Obj(obj);
}

// Append `n` bytes from `src` to a growing arena string buffer, growing
// it (copy-on-grow, since the arena is bump-only) when needed. Returns
// false on OOM.
static bool TemplateAppend(Arena& a, char*& buf, u32& len, u32& cap, const char* src, u32 n)
{
    if (len + n + 1 > cap)
    {
        u32 newCap = cap ? cap * 2 : 64;
        while (newCap < len + n + 1)
            newCap *= 2;
        char* nb = static_cast<char*>(a.Alloc(newCap, 1));
        if (!nb)
            return false;
        for (u32 i = 0; i < len; ++i)
            nb[i] = buf[i];
        buf = nb;
        cap = newCap;
    }
    for (u32 i = 0; i < n; ++i)
        buf[len + i] = src[i];
    len += n;
    return true;
}

// Evaluate a template literal: cook chunk[0] + ToString(expr[0]) +
// chunk[1] + … + chunk[kidCount]. Chunks live in keys[]/keyLens[]
// (kidCount+1 of them); interpolated expressions in kids[].
static Result<JsValue> EvalTemplate(Interp& I, const AstNode* n, Env* env)
{
    char* buf = nullptr;
    u32 len = 0;
    u32 cap = 0;
    const u32 chunkCount = n->kidCount + 1;
    for (u32 i = 0; i < chunkCount; ++i)
    {
        if (!TemplateAppend(I.arena, buf, len, cap, n->keys[i], n->keyLens[i]))
            return Err{ErrorCode::OutOfMemory};
        if (i < n->kidCount)
        {
            JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->kids[i], env));
            JsString* s = ToJsString(I, v);
            if (!s)
                return Err{ErrorCode::OutOfMemory};
            if (!TemplateAppend(I.arena, buf, len, cap, s->data, s->len))
                return Err{ErrorCode::OutOfMemory};
        }
    }
    return JsValue::Str(MakeString(I.arena, buf ? buf : "", len));
}

static Result<JsValue> EvalUnary(Interp& I, const AstNode* n, Env* env)
{
    if (n->op == Op::Typeof)
    {
        // typeof on a bare undefined identifier must not throw.
        if (n->a->kind == Ast::Ident)
        {
            JsValue tmp{};
            if (!EnvGet(env, n->a->str, n->a->strLen, tmp))
                return JsValue::Str(MakeString(I.arena, "undefined", 9));
        }
        JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->a, env));
        const char* ts = TypeofString(v);
        return JsValue::Str(MakeString(I.arena, ts, duetos::core::StrLen(ts)));
    }
    JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->a, env));
    switch (n->op)
    {
    case Op::Pos:
        if (v.IsNumber())
            return v;
        return JsValue::Float(NumberToSf32(v));
    case Op::Neg:
        if (v.IsNumber())
            return NumNeg(v);
        return JsValue::Float(Sf32Neg(NumberToSf32(v)));
    case Op::NotOp:
        return JsValue::Bool(!ToBoolean(v));
    default:
        return Err{ErrorCode::BadState};
    }
}

static Result<JsValue> EvalBinary(Interp& I, const AstNode* n, Env* env)
{
    JS_TRY_ASSIGN(JsValue a, EvalExpr(I, n->a, env));
    JS_TRY_ASSIGN(JsValue b, EvalExpr(I, n->b, env));

    // Object operands of arithmetic / relational / additive operators
    // coerce to a primitive first (default hint = valueOf-then-toString).
    // Equality (== / != / === / !==) does its own coercion in
    // LooseEquals, so leave object operands intact for those.
    if (n->op != Op::EqEq && n->op != Op::NotEq && n->op != Op::StrictEq && n->op != Op::StrictNotEq)
    {
        if (a.type == JsType::Object)
        {
            JS_TRY_ASSIGN(JsValue pa, ToPrimitive(I, a, /*stringHint=*/false));
            if (pa.type != JsType::Undefined)
                a = pa;
        }
        if (b.type == JsType::Object)
        {
            JS_TRY_ASSIGN(JsValue pb, ToPrimitive(I, b, /*stringHint=*/false));
            if (pb.type != JsType::Undefined)
                b = pb;
        }
    }

    switch (n->op)
    {
    case Op::Add:
    {
        // string concatenation if either side is a string
        if (a.type == JsType::String || b.type == JsType::String)
        {
            JsString* sa = ToJsString(I, a);
            JsString* sb = ToJsString(I, b);
            if (!sa || !sb)
                return Err{ErrorCode::OutOfMemory};
            u32 ln = sa->len + sb->len;
            char* buf = static_cast<char*>(I.arena.Alloc(ln + 1, 1));
            if (!buf)
                return Err{ErrorCode::OutOfMemory};
            for (u32 i = 0; i < sa->len; ++i)
                buf[i] = sa->data[i];
            for (u32 i = 0; i < sb->len; ++i)
                buf[sa->len + i] = sb->data[i];
            buf[ln] = '\0';
            JsString* js = I.arena.New<JsString>();
            if (!js)
                return Err{ErrorCode::OutOfMemory};
            js->data = buf;
            js->len = ln;
            return JsValue::Str(js);
        }
        return NumAdd(a, b);
    }
    case Op::Sub:
        return NumSub(a, b);
    case Op::Mul:
        return NumMul(a, b);
    case Op::Div:
        return NumDiv(a, b);
    case Op::Mod:
        return NumMod(a, b);
    case Op::Lt:
    case Op::Gt:
    case Op::Le:
    case Op::Ge:
    {
        // string ordering if both strings
        int cmp;
        if (a.type == JsType::String && b.type == JsType::String)
        {
            const JsString* x = a.as.str;
            const JsString* y = b.as.str;
            u32 m = x->len < y->len ? x->len : y->len;
            cmp = 0;
            for (u32 i = 0; i < m; ++i)
            {
                if (x->data[i] != y->data[i])
                {
                    cmp = (unsigned char)x->data[i] < (unsigned char)y->data[i] ? -1 : 1;
                    break;
                }
            }
            if (cmp == 0)
                cmp = x->len < y->len ? -1 : (x->len > y->len ? 1 : 0);
        }
        else
        {
            cmp = NumCompare(a, b);
            if (cmp == 2)
                return JsValue::Bool(false); // NaN comparisons are false
        }
        switch (n->op)
        {
        case Op::Lt:
            return JsValue::Bool(cmp < 0);
        case Op::Gt:
            return JsValue::Bool(cmp > 0);
        case Op::Le:
            return JsValue::Bool(cmp <= 0);
        case Op::Ge:
            return JsValue::Bool(cmp >= 0);
        default:
            break;
        }
        return JsValue::Bool(false);
    }
    case Op::EqEq:
        return JsValue::Bool(LooseEquals(I, a, b));
    case Op::NotEq:
        return JsValue::Bool(!LooseEquals(I, a, b));
    case Op::StrictEq:
        return JsValue::Bool(StrictEquals(a, b));
    case Op::StrictNotEq:
        return JsValue::Bool(!StrictEquals(a, b));
    default:
        return Err{ErrorCode::BadState};
    }
}

static Result<JsValue> EvalLogical(Interp& I, const AstNode* n, Env* env)
{
    JS_TRY_ASSIGN(JsValue a, EvalExpr(I, n->a, env));
    if (n->op == Op::And)
    {
        if (!ToBoolean(a))
            return a; // short-circuit, returns the falsy lhs
        return EvalExpr(I, n->b, env);
    }
    // Or
    if (ToBoolean(a))
        return a; // short-circuit, returns the truthy lhs
    return EvalExpr(I, n->b, env);
}

// Build a JsFunction closure from a Function/Arrow node.
static JsFunction* MakeClosure(Interp& I, const AstNode* n, Env* env)
{
    JsFunction* fn = I.arena.New<JsFunction>();
    if (!fn)
        return nullptr;
    fn->node = n;
    fn->closure = env;
    fn->nativeId = 0;
    fn->name = n->str;
    return fn;
}

// Assignment target write-back.
static Result<JsValue> DoAssign(Interp& I, const AstNode* target, const JsValue& val, Env* env)
{
    if (target->kind == Ast::Ident)
    {
        if (!EnvAssign(env, target->str, target->strLen, val))
        {
            // auto-global (sloppy mode): define on the global env.
            EnvDefine(I.global, I.arena, target->str, target->strLen, val);
        }
        return val;
    }
    if (target->kind == Ast::Member)
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, target->a, env));
        if (obj.type != JsType::Object)
            return Err{ErrorCode::BadState};
        // Host objects (DOM elements) intercept property writes first
        // (e.g. `el.id = 'x'` reflects into the attribute). A hook that
        // returns false didn't claim the write, so it falls through to
        // the plain property map.
        JsObject* o = obj.as.obj;
        if (o->hostSet)
        {
            JS_TRY_ASSIGN(bool handled, o->hostSet(I, o, target->str, target->strLen, val));
            if (handled)
                return val;
        }
        if (!ObjSet(o, I.arena, target->str, target->strLen, val))
            return Err{ErrorCode::OutOfMemory};
        return val;
    }
    if (target->kind == Ast::Index)
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, target->a, env));
        JS_TRY_ASSIGN(JsValue idx, EvalExpr(I, target->b, env));
        if (obj.type != JsType::Object)
            return Err{ErrorCode::BadState};
        if (obj.as.obj->isArray && idx.IsNumber() && idx.as.num.isInt && idx.as.num.ival >= 0)
        {
            if (!ArrSet(obj.as.obj, I.arena, u32(idx.as.num.ival), val))
                return Err{ErrorCode::OutOfMemory};
            return val;
        }
        JsString* k = ToJsString(I, idx);
        if (!k || !ObjSet(obj.as.obj, I.arena, k->data, k->len, val))
            return Err{ErrorCode::OutOfMemory};
        return val;
    }
    return Err{ErrorCode::BadState};
}

static Result<JsValue> EvalAssign(Interp& I, const AstNode* n, Env* env)
{
    if (n->op == Op::AssignPlain)
    {
        JS_TRY_ASSIGN(JsValue v, EvalExpr(I, n->b, env));
        return DoAssign(I, n->a, v, env);
    }
    // compound: read current target, apply op, write back.
    JS_TRY_ASSIGN(JsValue cur, EvalExpr(I, n->a, env));
    JS_TRY_ASSIGN(JsValue rhs, EvalExpr(I, n->b, env));
    JsValue res;
    switch (n->op)
    {
    case Op::AssignAdd:
        if (cur.type == JsType::String || rhs.type == JsType::String)
        {
            JsString* sa = ToJsString(I, cur);
            JsString* sb = ToJsString(I, rhs);
            u32 ln = sa->len + sb->len;
            char* buf = static_cast<char*>(I.arena.Alloc(ln + 1, 1));
            if (!buf)
                return Err{ErrorCode::OutOfMemory};
            for (u32 i = 0; i < sa->len; ++i)
                buf[i] = sa->data[i];
            for (u32 i = 0; i < sb->len; ++i)
                buf[sa->len + i] = sb->data[i];
            buf[ln] = '\0';
            JsString* js = I.arena.New<JsString>();
            js->data = buf;
            js->len = ln;
            res = JsValue::Str(js);
        }
        else
            res = NumAdd(cur, rhs);
        break;
    case Op::AssignSub:
        res = NumSub(cur, rhs);
        break;
    case Op::AssignMul:
        res = NumMul(cur, rhs);
        break;
    case Op::AssignDiv:
        res = NumDiv(cur, rhs);
        break;
    case Op::AssignMod:
        res = NumMod(cur, rhs);
        break;
    default:
        return Err{ErrorCode::BadState};
    }
    return DoAssign(I, n->a, res, env);
}

static Result<JsValue> EvalCall(Interp& I, const AstNode* n, Env* env)
{
    // Detect method calls (callee is Member/Index) so we can bind the
    // receiver for String/Array methods.
    JsValue recv = JsValue::Undefined();
    JsValue callee;
    const AstNode* ce = n->a;

    if (ce->kind == Ast::Member)
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, ce->a, env));
        recv = obj;
        JS_TRY_ASSIGN(JsValue m, GetMember(I, obj, ce->str, ce->strLen));
        callee = m;
    }
    else if (ce->kind == Ast::Index)
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, ce->a, env));
        JS_TRY_ASSIGN(JsValue idx, EvalExpr(I, ce->b, env));
        recv = obj;
        JsString* k = ToJsString(I, idx);
        JS_TRY_ASSIGN(JsValue m, GetMember(I, obj, k->data, k->len));
        callee = m;
    }
    else
    {
        JS_TRY_ASSIGN(JsValue c, EvalExpr(I, ce, env));
        callee = c;
    }

    if (!callee.IsCallable())
        return Err{ErrorCode::BadState};

    // Evaluate arguments.
    JsValue argbuf[16];
    u32 argc = n->kidCount < 16 ? n->kidCount : 16;
    for (u32 i = 0; i < argc; ++i)
    {
        JS_TRY_ASSIGN(JsValue av, EvalExpr(I, n->kids[i], env));
        argbuf[i] = av;
    }

    JsFunction* fn = callee.as.fn;
    // Host-callback methods (DOM bindings) dispatch through their C++
    // function pointer; everything else goes through the closed builtin
    // switch or the JS closure path.
    if (fn->nativeId == kNativeCallback && fn->nativeCall)
        return fn->nativeCall(I, recv, argbuf, argc, fn->nativeCtx);
    if (fn->nativeId != 0)
        return CallNative(I, fn->nativeId, recv, argbuf, argc);
    return CallFunction(I, fn, argbuf, argc, recv);
}

Result<JsValue> EvalExpr(Interp& I, const AstNode* n, Env* env)
{
    if (!I.Tick())
        return Err{ErrorCode::Timeout};
    if (!n)
        return JsValue::Undefined();

    switch (n->kind)
    {
    case Ast::NumberLit:
        return n->numIsInt ? JsValue::Int(n->numI) : JsValue::Float(n->numF);
    case Ast::StringLit:
        return JsValue::Str(MakeString(I.arena, n->str, n->strLen));
    case Ast::BoolLit:
        return JsValue::Bool(n->boolVal);
    case Ast::NullLit:
        return JsValue::Null();
    case Ast::UndefinedLit:
        return JsValue::Undefined();
    case Ast::Ident:
    {
        JsValue v{};
        if (EnvGet(env, n->str, n->strLen, v))
            return v;
        return JsValue::Undefined();
    }
    case Ast::ArrayLit:
        return EvalArrayLit(I, n, env);
    case Ast::ObjectLit:
        return EvalObjectLit(I, n, env);
    case Ast::Unary:
        return EvalUnary(I, n, env);
    case Ast::Binary:
        return EvalBinary(I, n, env);
    case Ast::Logical:
        return EvalLogical(I, n, env);
    case Ast::Assign:
        return EvalAssign(I, n, env);
    case Ast::Ternary:
    {
        JS_TRY_ASSIGN(JsValue c, EvalExpr(I, n->a, env));
        return EvalExpr(I, ToBoolean(c) ? n->b : n->c, env);
    }
    case Ast::Template:
        return EvalTemplate(I, n, env);
    case Ast::Member:
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, n->a, env));
        return GetMember(I, obj, n->str, n->strLen);
    }
    case Ast::Index:
    {
        JS_TRY_ASSIGN(JsValue obj, EvalExpr(I, n->a, env));
        JS_TRY_ASSIGN(JsValue idx, EvalExpr(I, n->b, env));
        if (obj.type == JsType::Object && obj.as.obj->isArray && idx.IsNumber() && idx.as.num.isInt &&
            idx.as.num.ival >= 0)
        {
            JsValue out;
            if (ArrGet(obj.as.obj, u32(idx.as.num.ival), out))
                return out;
            return JsValue::Undefined();
        }
        JsString* k = ToJsString(I, idx);
        return GetMember(I, obj, k->data, k->len);
    }
    case Ast::Call:
        return EvalCall(I, n, env);
    case Ast::Function:
    case Ast::Arrow:
    {
        JsFunction* fn = MakeClosure(I, n, env);
        if (!fn)
            return Err{ErrorCode::OutOfMemory};
        return JsValue::Fn(fn);
    }
    default:
        return Err{ErrorCode::BadState};
    }
}

// ----------------------- statement eval -----------------------

// Does the block introduce any binding that needs its own scope? Only
// var/let/const and function declarations do. Plain expression / control
// statements don't — so a loop body like `{}` or `{ s += i; }` reuses
// the parent env and allocates nothing per iteration (critical: a hot
// loop must not leak an Env into the arena every pass).
static bool BlockNeedsScope(const AstNode* n)
{
    for (u32 i = 0; i < n->kidCount; ++i)
    {
        const AstNode* s = n->kids[i];
        if (s && (s->kind == Ast::VarDecl || (s->kind == Ast::Function && s->str)))
            return true;
    }
    return false;
}

static Result<JsValue> EvalBlock(Interp& I, const AstNode* n, Env* parent, bool newScope)
{
    Env* env = parent;
    if (newScope && BlockNeedsScope(n))
    {
        env = EnvNew(I.arena, parent);
        if (!env)
            return Err{ErrorCode::OutOfMemory};
    }
    // Hoist named function declarations in this block.
    for (u32 i = 0; i < n->kidCount; ++i)
    {
        const AstNode* s = n->kids[i];
        if (s && s->kind == Ast::Function && s->str)
        {
            JsFunction* fn = I.arena.New<JsFunction>();
            if (!fn)
                return Err{ErrorCode::OutOfMemory};
            fn->node = s;
            fn->closure = env;
            fn->name = s->str;
            EnvDefine(env, I.arena, s->str, s->strLen, JsValue::Fn(fn));
        }
    }
    JsValue last = JsValue::Undefined();
    for (u32 i = 0; i < n->kidCount; ++i)
    {
        JS_TRY_ASSIGN(JsValue v, EvalStmt(I, n->kids[i], env));
        last = v;
        if (I.flow != Flow::Normal)
            break;
    }
    return last;
}

Result<JsValue> EvalStmt(Interp& I, const AstNode* n, Env* env)
{
    if (!I.Tick())
        return Err{ErrorCode::Timeout};
    if (!n)
        return JsValue::Undefined();

    switch (n->kind)
    {
    case Ast::VarDecl:
    {
        JsValue v = JsValue::Undefined();
        if (n->a)
        {
            JS_TRY_ASSIGN(JsValue iv, EvalExpr(I, n->a, env));
            v = iv;
        }
        if (!EnvDefine(env, I.arena, n->str, n->strLen, v))
            return Err{ErrorCode::OutOfMemory};
        return JsValue::Undefined();
    }
    case Ast::ExprStmt:
        return EvalExpr(I, n->a, env);
    case Ast::Block:
        return EvalBlock(I, n, env, true);
    case Ast::Function:
        // Declaration: already hoisted at block entry; nothing to do.
        return JsValue::Undefined();
    case Ast::If:
    {
        JS_TRY_ASSIGN(JsValue c, EvalExpr(I, n->a, env));
        if (ToBoolean(c))
            return EvalStmt(I, n->b, env);
        if (n->c)
            return EvalStmt(I, n->c, env);
        return JsValue::Undefined();
    }
    case Ast::While:
    {
        while (true)
        {
            if (!I.Tick())
                return Err{ErrorCode::Timeout};
            JS_TRY_ASSIGN(JsValue c, EvalExpr(I, n->a, env));
            if (!ToBoolean(c))
                break;
            JS_TRY(EvalStmt(I, n->b, env));
            if (I.flow == Flow::Break)
            {
                I.flow = Flow::Normal;
                break;
            }
            if (I.flow == Flow::Continue)
                I.flow = Flow::Normal;
            else if (I.flow == Flow::Return)
                break;
        }
        return JsValue::Undefined();
    }
    case Ast::For:
    {
        Env* loopEnv = EnvNew(I.arena, env);
        if (!loopEnv)
            return Err{ErrorCode::OutOfMemory};
        if (n->a)
            JS_TRY(EvalStmt(I, n->a, loopEnv));
        while (true)
        {
            if (!I.Tick())
                return Err{ErrorCode::Timeout};
            if (n->c)
            {
                JS_TRY_ASSIGN(JsValue c, EvalExpr(I, n->c, loopEnv));
                if (!ToBoolean(c))
                    break;
            }
            JS_TRY(EvalStmt(I, n->d, loopEnv));
            if (I.flow == Flow::Break)
            {
                I.flow = Flow::Normal;
                break;
            }
            if (I.flow == Flow::Return)
                break;
            if (I.flow == Flow::Continue)
                I.flow = Flow::Normal;
            if (n->b)
                JS_TRY(EvalExpr(I, n->b, loopEnv));
        }
        return JsValue::Undefined();
    }
    case Ast::Return:
    {
        JsValue v = JsValue::Undefined();
        if (n->a)
        {
            JS_TRY_ASSIGN(JsValue rv, EvalExpr(I, n->a, env));
            v = rv;
        }
        I.returnValue = v;
        I.flow = Flow::Return;
        return v;
    }
    case Ast::Break:
        I.flow = Flow::Break;
        return JsValue::Undefined();
    case Ast::Continue:
        I.flow = Flow::Continue;
        return JsValue::Undefined();
    case Ast::Program:
        return EvalBlock(I, n, env, false);
    default:
        // an expression used as a statement
        return EvalExpr(I, n, env);
    }
}

// ----------------------- function call -----------------------

Result<JsValue> CallFunction(Interp& I, JsFunction* fn, const JsValue* args, u32 argc, const JsValue& /*thisArr*/)
{
    if (I.depth >= I.maxDepth)
        return Err{ErrorCode::Overflow};
    // Native (kernel) stack-overflow guard. The logical depth cap above
    // cannot see real C++ stack consumption — each JS call level burns
    // several native frames (~15 KiB in debug) — so on the kernel's 64 KiB
    // arena stack a deep recursion would smash the guard page long before
    // `maxDepth`. When this thread runs on a kstack-arena slot, bail with
    // Overflow once the current frame is within kJsStackGuardMargin of the
    // slot's guard page. (Boot-context threads run on a larger non-arena
    // stack and are bounded by `maxDepth` alone.)
    {
        const u64 fr = reinterpret_cast<u64>(__builtin_frame_address(0));
        if (fr >= mm::kKernelStackArenaBase && fr < mm::kKernelStackArenaBase + mm::kKernelStackArenaBytes)
        {
            const u64 offInSlot = (fr - mm::kKernelStackArenaBase) % mm::kKernelStackSlotBytes;
            const u64 floor = mm::kKernelStackGuardPages * mm::kPageSize + kJsStackGuardMargin;
            if (offInSlot <= floor)
                return Err{ErrorCode::Overflow};
        }
    }
    I.depth++;

    Env* callEnv = EnvNew(I.arena, fn->closure);
    if (!callEnv)
    {
        I.depth--;
        return Err{ErrorCode::OutOfMemory};
    }

    const AstNode* node = fn->node;
    // bind params (node->kids are Ident params)
    for (u32 i = 0; i < node->kidCount; ++i)
    {
        const AstNode* p = node->kids[i];
        JsValue v = (i < argc) ? args[i] : JsValue::Undefined();
        EnvDefine(callEnv, I.arena, p->str, p->strLen, v);
    }

    const Flow savedFlow = I.flow;
    I.flow = Flow::Normal;

    Result<JsValue> body = EvalStmt(I, node->a, callEnv);
    I.depth--;
    if (!body)
    {
        I.flow = savedFlow;
        return body;
    }

    JsValue ret = JsValue::Undefined();
    if (I.flow == Flow::Return)
        ret = I.returnValue;
    I.flow = savedFlow;
    return ret;
}

} // namespace duetos::web::js
