#include "security/auth.h"

#include "log/klog.h"
#include "core/panic.h"
#include "util/random.h"

namespace duetos::core
{

namespace
{

struct Account
{
    bool in_use;
    AuthRole role;
    u8 salt[8];
    u64 hash; // iterated FNV-1a 64-bit, zero iff password is empty
    char name[kAuthNameMax];
};

constinit Account g_accounts[kAuthMaxAccounts] = {};

struct Session
{
    bool active;
    AuthRole role;
    char name[kAuthNameMax];
};

constinit Session g_session = {};

// Iteration count for the KDF. Deliberately modest — the hash is
// FNV, not a real PBKDF, and we want login latency under a tick
// on slow CPUs. Matches the "named seam" note in the header:
// bumping this or swapping the primitive is a one-file change.
constexpr u32 kHashIterations = 4096;

// FNV-1a 64-bit — offset basis + prime per the canonical spec.
constexpr u64 kFnvOffset = 0xCBF29CE484222325ULL;
constexpr u64 kFnvPrime = 0x100000001B3ULL;

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s != nullptr && s[n] != '\0')
    {
        ++n;
    }
    return n;
}

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
        if (a[i] == '\0')
        {
            return true;
        }
    }
}

void StrCopy(char* dst, const char* src, u32 cap)
{
    if (dst == nullptr || cap == 0)
    {
        return;
    }
    u32 i = 0;
    for (; i + 1 < cap && src != nullptr && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

// Validate a username / password: printable ASCII, no spaces,
// length within cap. Returns false on any violation.
bool IsValidAuthString(const char* s, u32 cap, bool allow_empty)
{
    if (s == nullptr)
    {
        return false;
    }
    const u32 n = StrLen(s);
    if (n == 0)
    {
        return allow_empty;
    }
    if (n + 1 > cap)
    {
        return false;
    }
    for (u32 i = 0; i < n; ++i)
    {
        const char c = s[i];
        if (c <= 0x20 || c >= 0x7F)
        {
            return false;
        }
    }
    return true;
}

// Produce a salted iterated FNV-1a hash of `password`. Empty
// passwords short-circuit to 0 — callers compare against 0 to
// detect "no password set". Non-empty passwords always get a
// full iteration pass so the timing is independent of password
// length across the iteration count.
u64 HashPassword(const char* password, const u8 salt[8])
{
    if (password == nullptr || password[0] == '\0')
    {
        return 0;
    }
    u64 h = kFnvOffset;
    for (u32 i = 0; i < 8; ++i)
    {
        h ^= static_cast<u64>(salt[i]);
        h *= kFnvPrime;
    }
    for (u32 i = 0; password[i] != '\0'; ++i)
    {
        h ^= static_cast<u64>(static_cast<u8>(password[i]));
        h *= kFnvPrime;
    }
    // Iterate on the running hash to burn a fixed time budget.
    for (u32 k = 0; k < kHashIterations; ++k)
    {
        h ^= (h >> 27);
        h *= kFnvPrime;
        h ^= (h << 13);
    }
    return h;
}

void GenerateSalt(u8 out[8])
{
    const u64 r = RandomU64();
    for (u32 i = 0; i < 8; ++i)
    {
        out[i] = static_cast<u8>((r >> (i * 8)) & 0xFF);
    }
}

Account* FindAccount(const char* username)
{
    if (username == nullptr)
    {
        return nullptr;
    }
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use && StrEq(g_accounts[i].name, username))
        {
            return &g_accounts[i];
        }
    }
    return nullptr;
}

Account* AllocAccount()
{
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
        {
            return &g_accounts[i];
        }
    }
    return nullptr;
}

bool StoreAccount(Account* a, const char* username, const char* password, AuthRole role)
{
    a->in_use = true;
    a->role = role;
    GenerateSalt(a->salt);
    a->hash = HashPassword(password, a->salt);
    StrCopy(a->name, username, kAuthNameMax);
    return true;
}

u32 CountAdmins()
{
    u32 n = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use && g_accounts[i].role == AuthRole::Admin)
        {
            ++n;
        }
    }
    return n;
}

} // namespace

void AuthInit()
{
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        g_accounts[i] = {};
    }
    g_session = {};
    Account* a = AllocAccount();
    StoreAccount(a, "admin", "admin", AuthRole::Admin);
    a = AllocAccount();
    StoreAccount(a, "guest", "", AuthRole::Guest);
    KLOG_INFO("auth", "seeded default accounts (admin, guest)");
}

bool AuthIsAuthenticated()
{
    return g_session.active;
}

const char* AuthCurrentUserName()
{
    return g_session.active ? g_session.name : "";
}

AuthRole AuthCurrentRole()
{
    return g_session.active ? g_session.role : AuthRole::Guest;
}

bool AuthIsAdmin()
{
    return g_session.active && g_session.role == AuthRole::Admin;
}

bool AuthVerify(const char* username, const char* password)
{
    const Account* a = FindAccount(username);
    if (a == nullptr)
    {
        // Burn an equivalent hash cycle against a throwaway salt
        // so a missing user doesn't respond faster than a bad
        // password against a real user.
        const u8 bogus_salt[8] = {};
        (void)HashPassword(password != nullptr ? password : "", bogus_salt);
        return false;
    }
    const u64 computed = HashPassword(password, a->salt);
    return computed == a->hash;
}

bool AuthLogin(const char* username, const char* password)
{
    if (!AuthVerify(username, password))
    {
        return false;
    }
    const Account* a = FindAccount(username);
    g_session.active = true;
    g_session.role = a->role;
    StrCopy(g_session.name, a->name, kAuthNameMax);
    KLOG_INFO("auth", "session begin");
    return true;
}

void AuthLogout()
{
    if (!g_session.active)
    {
        return;
    }
    g_session.active = false;
    g_session.name[0] = '\0';
    g_session.role = AuthRole::Guest;
    KLOG_INFO("auth", "session end");
}

bool AuthAddUser(const char* username, const char* password, AuthRole role)
{
    if (!IsValidAuthString(username, kAuthNameMax, false))
    {
        return false;
    }
    if (!IsValidAuthString(password, kAuthPasswordMax, true))
    {
        return false;
    }
    if (FindAccount(username) != nullptr)
    {
        return false;
    }
    Account* a = AllocAccount();
    if (a == nullptr)
    {
        return false;
    }
    return StoreAccount(a, username, password, role);
}

bool AuthDeleteUser(const char* username)
{
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    if (a->role == AuthRole::Admin && CountAdmins() <= 1)
    {
        return false;
    }
    const bool was_session_user = g_session.active && StrEq(g_session.name, a->name);
    a->in_use = false;
    a->hash = 0;
    a->name[0] = '\0';
    if (was_session_user)
    {
        AuthLogout();
    }
    return true;
}

bool AuthChangePassword(const char* username, const char* old_password, const char* new_password)
{
    if (!IsValidAuthString(new_password, kAuthPasswordMax, true))
    {
        return false;
    }
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    if (old_password != nullptr)
    {
        const u64 old_hash = HashPassword(old_password, a->salt);
        if (old_hash != a->hash)
        {
            return false;
        }
    }
    GenerateSalt(a->salt);
    a->hash = HashPassword(new_password, a->salt);
    return true;
}

u32 AuthAccountCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use)
        {
            ++n;
        }
    }
    return n;
}

bool AuthAccountAt(u32 idx, AccountView* view)
{
    if (view == nullptr)
    {
        return false;
    }
    u32 seen = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
        {
            continue;
        }
        if (seen == idx)
        {
            view->username = g_accounts[i].name;
            view->role = g_accounts[i].role;
            view->has_password = (g_accounts[i].hash != 0);
            return true;
        }
        ++seen;
    }
    return false;
}

bool AuthAccountByName(const char* username, AccountView* view)
{
    const Account* a = FindAccount(username);
    if (a == nullptr || view == nullptr)
    {
        return false;
    }
    view->username = a->name;
    view->role = a->role;
    view->has_password = (a->hash != 0);
    return true;
}

void AuthSelfTest()
{
    if (!AuthVerify("admin", "admin"))
    {
        Panic("auth", "self-test: seeded admin/admin rejected");
    }
    if (AuthVerify("admin", "wrong"))
    {
        Panic("auth", "self-test: wrong password for admin accepted");
    }
    if (AuthVerify("nobody", "x"))
    {
        Panic("auth", "self-test: unknown account accepted");
    }
    if (!AuthVerify("guest", ""))
    {
        Panic("auth", "self-test: empty password for guest rejected");
    }
    KLOG_INFO("auth", "self-test OK");
}

} // namespace duetos::core
