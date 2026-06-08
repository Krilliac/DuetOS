// test_omnibox_classify.cpp — hosted unit test for the browser omnibox
// URL-vs-search classifier.
//
// Covers: kernel/apps/browser/omnibox_classify.h
//   OmniboxLooksLikeUrl()      — is typed text a URL/host or a search query?
//   OmniboxBuildSearchUrl()    — percent-encode a query into a search URL
//
// Heuristic contract (Chromium-style "what you typed"): an explicit
// scheme, or a dotted host / localhost / IP literal with NO internal
// whitespace -> navigate as a URL; anything containing a space, or a
// single bare word with no dot -> search. This is what makes typing
// "google.com" navigate while "weather" searches, instead of the old
// behaviour where every bare word became a host -> DNS-fail -> blank page.

#include "host_test_helper.h"

#include "../../kernel/apps/browser/omnibox_classify.h"

using namespace duetos_host_test;
using duetos::apps::browser::OmniboxBuildSearchUrl;
using duetos::apps::browser::OmniboxLooksLikeUrl;

int main()
{
    // ---- URLs: navigate ----
    EXPECT_TRUE(OmniboxLooksLikeUrl("google.com"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("http://example.com"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("https://example.com/path?q=1"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("example.com/some/path"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("sub.domain.co.uk"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("192.168.1.1"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("localhost"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("localhost:8080"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("localhost/page"));
    EXPECT_TRUE(OmniboxLooksLikeUrl("duet://welcome")); // internal scheme page
    EXPECT_TRUE(OmniboxLooksLikeUrl("  google.com  ")); // surrounding spaces trimmed

    // ---- Search queries: not a URL ----
    EXPECT_FALSE(OmniboxLooksLikeUrl("weather"));
    EXPECT_FALSE(OmniboxLooksLikeUrl("news today"));
    EXPECT_FALSE(OmniboxLooksLikeUrl("hello world"));
    EXPECT_FALSE(OmniboxLooksLikeUrl("what is 2.5")); // dot present but multi-word -> search
    EXPECT_FALSE(OmniboxLooksLikeUrl("."));           // lone dot is not a host
    EXPECT_FALSE(OmniboxLooksLikeUrl(""));            // empty
    EXPECT_FALSE(OmniboxLooksLikeUrl("   "));         // whitespace only
    EXPECT_FALSE(OmniboxLooksLikeUrl(nullptr));       // null-safe

    // ---- Search URL construction (x-www-form-urlencoded query) ----
    char out[256];
    OmniboxBuildSearchUrl("hello world", out, sizeof(out));
    EXPECT_STREQ(out, "https://duckduckgo.com/html/?q=hello+world");

    OmniboxBuildSearchUrl("c++ & rust", out, sizeof(out));
    EXPECT_STREQ(out, "https://duckduckgo.com/html/?q=c%2B%2B+%26+rust");

    OmniboxBuildSearchUrl("plain", out, sizeof(out));
    EXPECT_STREQ(out, "https://duckduckgo.com/html/?q=plain");

    // Leading spaces in the query are trimmed before encoding.
    OmniboxBuildSearchUrl("  spaced", out, sizeof(out));
    EXPECT_STREQ(out, "https://duckduckgo.com/html/?q=spaced");

    return finish_main("omnibox_classify");
}
