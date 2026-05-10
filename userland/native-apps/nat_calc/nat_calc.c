/*
 * DuetOS — portable native arithmetic-expression evaluator, v0.
 *
 * Single-pass recursive-descent parser for a tiny grammar:
 *
 *   expr   := term (('+' | '-') term)*
 *   term   := factor (('*' | '/') factor)*
 *   factor := NUMBER | '(' expr ')'
 *   NUMBER := [0-9]+
 *
 * Evaluates a hard-coded suite of expressions on stdin-free
 * boot to prove the pattern handles real logic without leaning
 * on the in-kernel calculator's widget framework. Each result
 * is printed with a `[nat-calc]` sentinel; the boot smoke can
 * grep for these to detect regressions in the native-app
 * pipeline (the actual arithmetic is well-defined; if any
 * answer drifts, libc / native build is broken).
 */

#include "stdio.h"
#include "string.h"
#include "unistd.h"

typedef struct
{
    const char* p;
    int error;
} Parser;

static long parse_expr(Parser* s);

static void skip_ws(Parser* s)
{
    while (*s->p == ' ' || *s->p == '\t')
        ++s->p;
}

static long parse_factor(Parser* s)
{
    skip_ws(s);
    if (*s->p == '(')
    {
        ++s->p;
        const long v = parse_expr(s);
        skip_ws(s);
        if (*s->p != ')')
        {
            s->error = 1;
            return 0;
        }
        ++s->p;
        return v;
    }
    if (*s->p < '0' || *s->p > '9')
    {
        s->error = 1;
        return 0;
    }
    long v = 0;
    while (*s->p >= '0' && *s->p <= '9')
    {
        v = v * 10 + (*s->p - '0');
        ++s->p;
    }
    return v;
}

static long parse_term(Parser* s)
{
    long v = parse_factor(s);
    while (!s->error)
    {
        skip_ws(s);
        const char op = *s->p;
        if (op != '*' && op != '/')
            break;
        ++s->p;
        const long r = parse_factor(s);
        if (s->error)
            break;
        if (op == '*')
        {
            v *= r;
        }
        else
        {
            if (r == 0)
            {
                s->error = 2; /* divide by zero */
                break;
            }
            v /= r;
        }
    }
    return v;
}

static long parse_expr(Parser* s)
{
    long v = parse_term(s);
    while (!s->error)
    {
        skip_ws(s);
        const char op = *s->p;
        if (op != '+' && op != '-')
            break;
        ++s->p;
        const long r = parse_term(s);
        if (s->error)
            break;
        v = (op == '+') ? v + r : v - r;
    }
    return v;
}

/* Evaluate `expr`. On parse error, returns 0 and writes a
 * `[nat-calc] ERR ...` line; otherwise prints the result. */
static int eval_one(const char* expr, long expected)
{
    Parser s = {expr, 0};
    const long got = parse_expr(&s);
    skip_ws(&s);
    if (*s.p != '\0')
        s.error = 1;
    if (s.error)
    {
        puts_str("[nat-calc] ERR  expr='");
        puts_str(expr);
        puts_str("' code=");
        print_int(s.error);
        puts_char('\n');
        return 1;
    }
    if (got != expected)
    {
        puts_str("[nat-calc] FAIL expr='");
        puts_str(expr);
        puts_str("' got=");
        print_int(got);
        puts_str(" expected=");
        print_int(expected);
        puts_char('\n');
        return 1;
    }
    puts_str("[nat-calc] OK   expr='");
    puts_str(expr);
    puts_str("' = ");
    print_int(got);
    puts_char('\n');
    return 0;
}

int main(void)
{
    println("[nat-calc] portable native arithmetic eval — second sentinel");
    int failures = 0;
    /* A spread of cases that exercise precedence + parens + the
     * unary-minus-via-zero subtraction trick. */
    failures += eval_one("1+2", 3);
    failures += eval_one("2*3+4", 10);
    failures += eval_one("2+3*4", 14);
    failures += eval_one("(2+3)*4", 20);
    failures += eval_one("100/4", 25);
    failures += eval_one("0-7", -7);
    failures += eval_one("(((10+5)*2-4)/2)", 13);
    if (failures == 0)
    {
        println("[nat-calc] all eval cases passed");
        return 0xCA1C;
    }
    puts_str("[nat-calc] ");
    print_int(failures);
    println(" eval case(s) FAILED");
    return 0xBAD;
}
