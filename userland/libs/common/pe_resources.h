#ifndef DUETOS_USERLAND_PE_RESOURCES_H
#define DUETOS_USERLAND_PE_RESOURCES_H

/*
 * Freestanding PE `.rsrc` (resource-directory) walker shared by the
 * x86_64 and i386 Win32 companion DLLs.
 *
 * WHY THIS IS A USERLAND HEADER AND NOT A SYSCALL
 *   The kernel PE loader already maps the whole image into the guest's
 *   own address space: `MapHeaders` copies SizeOfHeaders bytes to
 *   ImageBase (RO+NX) and `MapSection` maps every section at
 *   ImageBase+VirtualAddress for max(VirtualSize, SizeOfRawData) bytes,
 *   zero-filled past the raw tail. `dll_loader.cpp` does the same for
 *   preloaded DLLs. So a DLL holding an HMODULE can reach the resource
 *   tree with plain pointer arithmetic — no new syscall, no new kernel
 *   surface, and therefore no new way for a guest PE to reach past the
 *   subsystem boundary. Everything here runs in the guest's own context
 *   on the guest's own pages.
 *
 * THREAT MODEL
 *   Every byte walked below comes from an attacker-controllable guest
 *   binary. A malformed tree must FAIL CLOSED — return "not found" —
 *   and must never form a pointer outside the mapped image. Two rules
 *   enforce that:
 *     1. Every read goes through `duet_res_at`, which resolves an RVA
 *        to a pointer only when the whole span lies inside one mapped
 *        section (span computed exactly as the kernel's MapSection
 *        computes it) or inside the mapped header block.
 *     2. The three-level walk is written as three flat loops with a
 *        fixed depth. The format has exactly three levels, so there is
 *        no recursion and a self-referential subdirectory pointer can
 *        cost at most one extra level of iteration, never a cycle.
 *   Entry counts are u16 pairs, and every entry must clear rule 1, so
 *   loop trip counts are bounded by the containing section's size.
 *
 * WHY NOT REUSE pe_unwind_bounds.h
 *   That header's DUET_PE_VIEW is PE32+ only (it rejects anything whose
 *   optional-header magic is not 0x20B) and it requires a well-formed
 *   `.pdata`. Resources have to work for i386 PE32 images with no
 *   exception directory at all, so the bounds primitives are restated
 *   here rather than the view being widened and both callers put at
 *   risk. The two headers deliberately do not include each other.
 *
 * PROVENANCE
 *   Layout per the PE/COFF specification, section 6.9 ("The .rsrc
 *   Section"). String-table bundling per the documented LoadString
 *   contract: string `id` lives at index `id % 16` of the RT_STRING
 *   resource whose integer name is `(id / 16) + 1`.
 *   Added 2026-07-28 for the `.rsrc` parser slice.
 */

#if defined(__clang__) || defined(__GNUC__)
#define DUET_RES_INLINE static inline __attribute__((unused))
#else
#define DUET_RES_INLINE static inline
#endif

/* Bytes of the image guaranteed readable before SizeOfHeaders has been
 * validated. MapHeaders always maps at least one page at ImageBase, so
 * the DOS stub, the NT headers and the section table (which the PE spec
 * requires to sit inside SizeOfHeaders) can be probed within it. */
#define DUET_RES_HEADER_PROBE 0x1000u

#define DUET_RES_SECTION_HEADER_SIZE 40u
#define DUET_RES_DIR_HEADER_SIZE 16u
#define DUET_RES_DIR_ENTRY_SIZE 8u
#define DUET_RES_DATA_ENTRY_SIZE 16u
#define DUET_RES_HIGH_BIT 0x80000000u

/* Standard RT_* resource type ordinals used by the callers below. */
#define DUET_RES_TYPE_CURSOR 1u
#define DUET_RES_TYPE_BITMAP 2u
#define DUET_RES_TYPE_ICON 3u
#define DUET_RES_TYPE_MENU 4u
#define DUET_RES_TYPE_DIALOG 5u
#define DUET_RES_TYPE_STRING 6u
#define DUET_RES_TYPE_ACCELERATOR 9u
#define DUET_RES_TYPE_GROUP_CURSOR 12u
#define DUET_RES_TYPE_GROUP_ICON 14u
#define DUET_RES_TYPE_VERSION 16u
#define DUET_RES_TYPE_MANIFEST 24u

/* A parsed, bounds-checked view of one mapped module's resource tree. */
typedef struct
{
    const unsigned char* base; /* module base VA == HMODULE */
    unsigned int image_size;   /* OptionalHeader.SizeOfImage */
    unsigned int headers_size; /* OptionalHeader.SizeOfHeaders */
    unsigned int sections_rva; /* section table offset from `base` */
    unsigned int section_count;
    unsigned int dir_rva;  /* DataDirectory[2].VirtualAddress */
    unsigned int dir_span; /* readable bytes from dir_rva onward */
} DUET_RES_VIEW;

/* A level-1/level-2 lookup key: either an integer ordinal or a
 * (non-NUL-terminated) UTF-16 name. Mirrors MAKEINTRESOURCE. */
typedef struct
{
    int by_name;                /* 0 = match `id`, 1 = match `name` */
    unsigned int id;            /* integer ordinal when by_name == 0 */
    const unsigned short* name; /* UTF-16 chars when by_name == 1 */
    unsigned int name_len;      /* chars in `name`, excluding any NUL */
} DUET_RES_KEY;

DUET_RES_INLINE unsigned short duet_res_u16(const unsigned char* p)
{
    return (unsigned short)((unsigned short)p[0] | (unsigned short)((unsigned short)p[1] << 8));
}

DUET_RES_INLINE unsigned int duet_res_u32(const unsigned char* p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* Overflow-free "does [rva, rva+span) fit inside [0, limit)". */
DUET_RES_INLINE int duet_res_range(unsigned int rva, unsigned int span, unsigned int limit)
{
    return rva <= limit && span <= limit - rva;
}

/* In-memory footprint of one section, computed exactly the way the
 * kernel's MapSection computes it: max(VirtualSize, SizeOfRawData). Any
 * byte inside that extent is mapped (zero-filled past the raw tail). */
DUET_RES_INLINE unsigned int duet_res_section_span(const unsigned char* section)
{
    const unsigned int virtual_size = duet_res_u32(section + 8u);
    const unsigned int raw_size = duet_res_u32(section + 16u);
    return virtual_size > raw_size ? virtual_size : raw_size;
}

/* Contiguous mapped bytes available from `rva`, or 0 when `rva` is not
 * mapped. Used to bound spans whose length is itself read out of the
 * image and therefore cannot be trusted. */
DUET_RES_INLINE unsigned int duet_res_mapped_span_from(const DUET_RES_VIEW* view, unsigned int rva)
{
    unsigned int best = 0u;
    unsigned int i;
    if (view == (const DUET_RES_VIEW*)0 || rva > view->image_size)
        return 0u;
    if (rva <= view->headers_size)
        best = view->headers_size - rva;
    for (i = 0; i < view->section_count; ++i)
    {
        const unsigned char* section = view->base + view->sections_rva + i * DUET_RES_SECTION_HEADER_SIZE;
        const unsigned int section_rva = duet_res_u32(section + 12u);
        const unsigned int section_span = duet_res_section_span(section);
        if (rva >= section_rva && rva - section_rva <= section_span)
        {
            const unsigned int avail = section_span - (rva - section_rva);
            if (avail > best)
                best = avail;
        }
    }
    return best;
}

/* The one gate every resource read goes through. Resolves an image RVA
 * to a readable pointer, or returns NULL when the requested span is not
 * wholly inside a mapped extent. A zero-length span is rejected so a
 * caller can never mistake "empty" for "valid". */
DUET_RES_INLINE const unsigned char* duet_res_at(const DUET_RES_VIEW* view, unsigned int rva, unsigned int span)
{
    if (view == (const DUET_RES_VIEW*)0 || span == 0u)
        return (const unsigned char*)0;
    if (!duet_res_range(rva, span, view->image_size))
        return (const unsigned char*)0;
    if (span > duet_res_mapped_span_from(view, rva))
        return (const unsigned char*)0;
    return view->base + rva;
}

/* As duet_res_at, but for an offset relative to the resource directory
 * base. The tree walk uses this exclusively.
 *
 * The memory-safety gate is duet_res_at underneath — a negative control
 * (delete the clamp below, run tests/host/test_pe_resources) shows the
 * malformed-tree cases are still caught. The clamp is here for two
 * narrower reasons: it keeps the walk semantically inside the directory
 * rather than merely inside some mapped section, and it proves
 * `off + span` fits the section BEFORE `dir_rva + off` is computed, so
 * that sum cannot wrap a u32 into an unrelated part of the image. */
DUET_RES_INLINE const unsigned char* duet_res_dir_at(const DUET_RES_VIEW* view, unsigned int off, unsigned int span)
{
    if (view == (const DUET_RES_VIEW*)0 || span == 0u)
        return (const unsigned char*)0;
    if (!duet_res_range(off, span, view->dir_span))
        return (const unsigned char*)0;
    return duet_res_at(view, view->dir_rva + off, span);
}

/* Parse a mapped module into a resource view.
 *
 * Returns 1 when the module has a usable resource directory, 0 when it
 * has none or the headers do not parse. Both PE32 (0x10B) and PE32+
 * (0x20B) are accepted; the only layout difference that matters here is
 * where DataDirectory starts inside the optional header. */
DUET_RES_INLINE int duet_res_init(const void* module_base, DUET_RES_VIEW* out)
{
    const unsigned char* image;
    const unsigned char* nt;
    const unsigned char* optional;
    unsigned int e_lfanew;
    unsigned int optional_rva;
    unsigned int optional_size;
    unsigned int optional_magic;
    unsigned int data_dir_off;
    unsigned int data_dir_count;
    unsigned int sections_rva;
    unsigned int section_count;
    unsigned int image_size;
    unsigned int headers_size;
    unsigned int dir_rva;
    unsigned int dir_declared;
    unsigned int dir_span;
    unsigned long long sections_bytes;

    if (module_base == (const void*)0 || out == (DUET_RES_VIEW*)0)
        return 0;
    image = (const unsigned char*)module_base;
    if (image[0] != 'M' || image[1] != 'Z')
        return 0;

    e_lfanew = duet_res_u32(image + 0x3Cu);
    if (e_lfanew < 0x40u || !duet_res_range(e_lfanew, 24u, DUET_RES_HEADER_PROBE))
        return 0;
    nt = image + e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0u || nt[3] != 0u)
        return 0;

    section_count = duet_res_u16(nt + 6u);
    optional_size = duet_res_u16(nt + 20u);
    optional_rva = e_lfanew + 24u;
    if (section_count == 0u || !duet_res_range(optional_rva, optional_size, DUET_RES_HEADER_PROBE))
        return 0;
    optional = image + optional_rva;

    /* PE32:  magic 0x10B, DataDirectory at optional+96, SizeOfImage at
     *        +56, SizeOfHeaders at +60, NumberOfRvaAndSizes at +92.
     * PE32+: magic 0x20B, DataDirectory at optional+112, same
     *        SizeOfImage / SizeOfHeaders offsets, count at +108. */
    if (optional_size < 4u)
        return 0;
    optional_magic = duet_res_u16(optional);
    if (optional_magic == 0x10Bu)
        data_dir_off = 96u;
    else if (optional_magic == 0x20Bu)
        data_dir_off = 112u;
    else
        return 0;
    if (optional_size < data_dir_off)
        return 0;
    data_dir_count = duet_res_u32(optional + data_dir_off - 4u);

    /* DataDirectory[2] is the resource table. A module with fewer than
     * three entries simply has no resources. */
    if (data_dir_count < 3u)
        return 0;
    if (optional_size < data_dir_off + 3u * 8u)
        return 0;

    image_size = duet_res_u32(optional + 56u);
    headers_size = duet_res_u32(optional + 60u);
    sections_rva = optional_rva + optional_size;
    sections_bytes = (unsigned long long)section_count * (unsigned long long)DUET_RES_SECTION_HEADER_SIZE;
    if (headers_size < sections_rva || headers_size > image_size || sections_rva > DUET_RES_HEADER_PROBE ||
        sections_bytes > (unsigned long long)(DUET_RES_HEADER_PROBE - sections_rva) ||
        sections_bytes > (unsigned long long)(headers_size - sections_rva))
        return 0;

    dir_rva = duet_res_u32(optional + data_dir_off + 2u * 8u);
    dir_declared = duet_res_u32(optional + data_dir_off + 2u * 8u + 4u);
    if (dir_rva == 0u || dir_declared < DUET_RES_DIR_HEADER_SIZE)
        return 0;

    out->base = image;
    out->image_size = image_size;
    out->headers_size = headers_size;
    out->sections_rva = sections_rva;
    out->section_count = section_count;
    out->dir_rva = dir_rva;
    out->dir_span = 0u;

    /* The tree bound is the mapped extent of the section holding the
     * directory, NOT DataDirectory[2].Size. Real linkers under-declare
     * that Size often enough that trusting it rejects legitimate
     * binaries; the section extent is what the kernel actually mapped,
     * so it is both the honest bound and the safe one. The declared
     * size is still required to fit inside it, which rejects a header
     * that claims a directory larger than its own section. */
    dir_span = duet_res_mapped_span_from(out, dir_rva);
    if (dir_span < DUET_RES_DIR_HEADER_SIZE || dir_declared > dir_span)
        return 0;
    out->dir_span = dir_span;
    return 1;
}

/* Total entries in the directory at `dir_off`, and the offset of its
 * first entry. Returns 0 when the directory header is out of bounds. */
DUET_RES_INLINE unsigned int duet_res_dir_count(const DUET_RES_VIEW* view, unsigned int dir_off,
                                                unsigned int* out_named)
{
    const unsigned char* dir = duet_res_dir_at(view, dir_off, DUET_RES_DIR_HEADER_SIZE);
    unsigned int named;
    unsigned int ids;
    if (dir == (const unsigned char*)0)
        return 0;
    named = duet_res_u16(dir + 12u);
    ids = duet_res_u16(dir + 14u);
    if (out_named != (unsigned int*)0)
        *out_named = named;
    return named + ids;
}

/* Decode entry `index` of the directory at `dir_off`.
 *
 * On success writes the entry's name (ordinal or UTF-16 key), the child
 * offset, and whether that child is a subdirectory. Returns 1/0. */
DUET_RES_INLINE int duet_res_dir_entry(const DUET_RES_VIEW* view, unsigned int dir_off, unsigned int index,
                                       DUET_RES_KEY* out_key, unsigned int* out_child, int* out_is_dir)
{
    const unsigned char* entry;
    unsigned int entry_off;
    unsigned int name_field;
    unsigned int child_field;

    if (out_key == (DUET_RES_KEY*)0 || out_child == (unsigned int*)0 || out_is_dir == (int*)0)
        return 0;
    if (index > (0xFFFFFFFFu - DUET_RES_DIR_HEADER_SIZE) / DUET_RES_DIR_ENTRY_SIZE)
        return 0;
    entry_off = dir_off + DUET_RES_DIR_HEADER_SIZE + index * DUET_RES_DIR_ENTRY_SIZE;
    entry = duet_res_dir_at(view, entry_off, DUET_RES_DIR_ENTRY_SIZE);
    if (entry == (const unsigned char*)0)
        return 0;

    name_field = duet_res_u32(entry);
    child_field = duet_res_u32(entry + 4u);
    out_key->by_name = 0;
    out_key->id = 0u;
    out_key->name = (const unsigned short*)0;
    out_key->name_len = 0u;

    if ((name_field & DUET_RES_HIGH_BIT) != 0u)
    {
        /* IMAGE_RESOURCE_DIR_STRING_U: u16 Length, then Length UTF-16
         * chars, NOT NUL-terminated. Both the header and the character
         * array are bounded before any pointer is handed out. */
        const unsigned int string_off = name_field & ~DUET_RES_HIGH_BIT;
        const unsigned char* string_header = duet_res_dir_at(view, string_off, 2u);
        unsigned int chars;
        if (string_header == (const unsigned char*)0)
            return 0;
        chars = duet_res_u16(string_header);
        if (chars != 0u)
        {
            const unsigned char* body;
            if (chars > (0xFFFFFFFFu - 2u) / 2u)
                return 0;
            body = duet_res_dir_at(view, string_off + 2u, chars * 2u);
            if (body == (const unsigned char*)0)
                return 0;
            out_key->name = (const unsigned short*)(const void*)body;
        }
        out_key->by_name = 1;
        out_key->name_len = chars;
    }
    else
    {
        out_key->id = name_field;
    }

    *out_is_dir = (child_field & DUET_RES_HIGH_BIT) != 0u;
    *out_child = child_field & ~DUET_RES_HIGH_BIT;
    return 1;
}

/* Case-insensitive ASCII fold, which is what the PE resource compiler
 * and the Win32 loader both use for named resources. */
DUET_RES_INLINE unsigned short duet_res_fold(unsigned short c)
{
    if (c >= (unsigned short)'a' && c <= (unsigned short)'z')
        return (unsigned short)(c - 32u);
    return c;
}

DUET_RES_INLINE int duet_res_key_equal(const DUET_RES_KEY* a, const DUET_RES_KEY* b)
{
    unsigned int i;
    if (a == (const DUET_RES_KEY*)0 || b == (const DUET_RES_KEY*)0)
        return 0;
    if (a->by_name != b->by_name)
        return 0;
    if (!a->by_name)
        return a->id == b->id;
    if (a->name_len != b->name_len)
        return 0;
    for (i = 0; i < a->name_len; ++i)
    {
        if (duet_res_fold(a->name[i]) != duet_res_fold(b->name[i]))
            return 0;
    }
    return 1;
}

/* ---- Named (string) resource lookup ----
 *
 * A directory entry's NameOffsetOrId field is a discriminated union.
 * High bit SET: the low 31 bits are a directory-relative offset to an
 * IMAGE_RESOURCE_DIR_STRING_U — a u16 Length followed by exactly
 * Length UTF-16 code units, with NO NUL terminator. High bit CLEAR:
 * the field is an integer ordinal. Both shapes are legal at the Type
 * and Name levels, and `.rc` sources use both.
 *
 * The icon / cursor / bitmap decoders below therefore come in two
 * forms. The `_key` form takes a DUET_RES_KEY and accepts either shape:
 *   duet_res_pick_icon_key, duet_res_bitmap_info_key,
 *   duet_res_decode_bitmap_key
 * The original integer-only names are kept as thin wrappers that build
 * an ordinal key, so every existing ordinal caller is unaffected.
 * Keys are built with duet_res_key_id / duet_res_key_name, and a
 * caller holding a NUL-terminated LPCWSTR measures it first with
 * duet_res_name_len.
 *
 * Only the Name level (level 2) is variable in practice for these
 * callers: the Type level is a fixed RT_* ordinal, and the RT_ICON /
 * RT_CURSOR members an RT_GROUP_ICON / RT_GROUP_CURSOR directory
 * points at are integer nIDs by format definition.
 *
 * Comparison is ASCII case-insensitive (a-z folded to A-Z), which is
 * what the resource compiler and the Windows loader both do.
 *
 * A DUET_RES_KEY BORROWS its characters — it never copies them — so
 * the buffer must outlive the key.
 *
 * Bounds: the string offset and the Length*2 byte span are both
 * validated against the mapped resource-section extent (duet_res_dir_at
 * over duet_res_at) BEFORE any code unit is read, in duet_res_dir_entry.
 * A hostile directory therefore cannot steer a read outside the mapped
 * image; a failed validation makes the lookup report "not found"
 * without having dereferenced anything.
 */

/* Key constructors.
 *
 * Every caller that builds a DUET_RES_KEY by hand has to zero all four
 * fields or the comparison above reads an uninitialised `name_len`, so
 * the two legal shapes get one constructor each. `duet_res_key_name`
 * takes a counted string because IMAGE_RESOURCE_DIR_STRING_U is counted
 * and unterminated; a caller holding a NUL-terminated LPCWSTR measures
 * it with duet_res_name_len first. */
DUET_RES_INLINE DUET_RES_KEY duet_res_key_id(unsigned int id)
{
    DUET_RES_KEY k;
    k.by_name = 0;
    k.id = id;
    k.name = (const unsigned short*)0;
    k.name_len = 0u;
    return k;
}

DUET_RES_INLINE DUET_RES_KEY duet_res_key_name(const unsigned short* name, unsigned int len)
{
    DUET_RES_KEY k;
    k.by_name = 1;
    k.id = 0u;
    k.name = name;
    k.name_len = len;
    if (name == (const unsigned short*)0)
        k.name_len = 0u;
    return k;
}

/* Length of a NUL-terminated UTF-16 string, capped at 0xFFFF because
 * that is the widest IMAGE_RESOURCE_DIR_STRING_U a Length field can
 * describe — a longer caller string can never match anything, so the
 * cap costs no matches and bounds the scan of a non-terminated buffer. */
DUET_RES_INLINE unsigned int duet_res_name_len(const unsigned short* s)
{
    unsigned int n = 0u;
    if (s == (const unsigned short*)0)
        return 0u;
    while (s[n] != 0u && n < 0xFFFFu)
        ++n;
    return n;
}

/* Find the child offset of the entry matching `key` in the directory at
 * `dir_off`. Returns 1 on hit. */
DUET_RES_INLINE int duet_res_lookup(const DUET_RES_VIEW* view, unsigned int dir_off, const DUET_RES_KEY* key,
                                    unsigned int* out_child, int* out_is_dir)
{
    const unsigned int total = duet_res_dir_count(view, dir_off, (unsigned int*)0);
    unsigned int i;
    for (i = 0; i < total; ++i)
    {
        DUET_RES_KEY found;
        unsigned int child;
        int is_dir;
        if (!duet_res_dir_entry(view, dir_off, i, &found, &child, &is_dir))
            return 0; /* fail closed: a truncated table ends the search */
        if (duet_res_key_equal(&found, key))
        {
            *out_child = child;
            *out_is_dir = is_dir;
            return 1;
        }
    }
    return 0;
}

/* Resolve the language level (level 3) of the tree.
 *
 * `want_lang != 0` asks for a specific LANGID first. The fallback order
 * — requested, then LANG_NEUTRAL, then the first entry present — is the
 * behaviour a Win32 caller relies on: a single-language binary stores
 * everything under one LANGID and expects FindResource to find it
 * regardless of the thread locale. */
DUET_RES_INLINE int duet_res_pick_language(const DUET_RES_VIEW* view, unsigned int lang_dir_off, unsigned int lang,
                                           int want_lang, unsigned int* out_data_off)
{
    DUET_RES_KEY key;
    unsigned int child;
    int is_dir;

    key.by_name = 0;
    key.name = (const unsigned short*)0;
    key.name_len = 0u;

    if (want_lang)
    {
        key.id = lang;
        if (duet_res_lookup(view, lang_dir_off, &key, &child, &is_dir) && !is_dir)
        {
            *out_data_off = child;
            return 1;
        }
        key.id = 0u; /* LANG_NEUTRAL */
        if (duet_res_lookup(view, lang_dir_off, &key, &child, &is_dir) && !is_dir)
        {
            *out_data_off = child;
            return 1;
        }
    }

    /* First entry present. The level-3 children are data entries, so a
     * subdirectory here is malformed and is skipped rather than walked
     * — that is what keeps the depth fixed at three. */
    {
        const unsigned int total = duet_res_dir_count(view, lang_dir_off, (unsigned int*)0);
        unsigned int i;
        for (i = 0; i < total; ++i)
        {
            DUET_RES_KEY found;
            if (!duet_res_dir_entry(view, lang_dir_off, i, &found, &child, &is_dir))
                return 0;
            if (!is_dir)
            {
                *out_data_off = child;
                return 1;
            }
        }
    }
    return 0;
}

/* The full three-level walk: type -> name -> language -> data entry.
 *
 * On success writes the resource bytes' image RVA and byte count, both
 * already validated to lie inside a mapped section. Returns 1/0. */
DUET_RES_INLINE int duet_res_find(const DUET_RES_VIEW* view, const DUET_RES_KEY* type, const DUET_RES_KEY* name,
                                  unsigned int lang, int want_lang, unsigned int* out_rva, unsigned int* out_size)
{
    unsigned int name_dir_off;
    unsigned int lang_dir_off;
    unsigned int data_off;
    const unsigned char* data_entry;
    unsigned int data_rva;
    unsigned int data_size;
    int is_dir;

    if (view == (const DUET_RES_VIEW*)0 || out_rva == (unsigned int*)0 || out_size == (unsigned int*)0)
        return 0;
    if (!duet_res_lookup(view, 0u, type, &name_dir_off, &is_dir) || !is_dir)
        return 0;
    if (!duet_res_lookup(view, name_dir_off, name, &lang_dir_off, &is_dir) || !is_dir)
        return 0;
    if (!duet_res_pick_language(view, lang_dir_off, lang, want_lang, &data_off))
        return 0;

    data_entry = duet_res_dir_at(view, data_off, DUET_RES_DATA_ENTRY_SIZE);
    if (data_entry == (const unsigned char*)0)
        return 0;
    data_rva = duet_res_u32(data_entry);
    data_size = duet_res_u32(data_entry + 4u);
    /* OffsetToData is an image RVA, not a directory-relative offset —
     * it may legitimately point outside .rsrc — so it is bounded
     * against the whole mapped image rather than the directory. */
    if (data_size == 0u || duet_res_at(view, data_rva, data_size) == (const unsigned char*)0)
        return 0;
    *out_rva = data_rva;
    *out_size = data_size;
    return 1;
}

/* Locate string-table entry `string_id`.
 *
 * RT_STRING resources are bundles of 16 counted UTF-16 strings. Bundle
 * `(string_id / 16) + 1` holds the string, and `string_id % 16` selects
 * it within the bundle. Each entry is a u16 character count followed by
 * exactly that many UTF-16 code units, with NO terminator — a count of
 * zero means "this slot is unused", which is the same as absent.
 *
 * On success `*out_chars` points into the mapped image (read-only) and
 * `*out_len` is the character count. Returns 1/0. */
DUET_RES_INLINE int duet_res_find_string(const DUET_RES_VIEW* view, unsigned int string_id, unsigned int lang,
                                         int want_lang, const unsigned short** out_chars, unsigned int* out_len)
{
    DUET_RES_KEY type;
    DUET_RES_KEY name;
    unsigned int rva;
    unsigned int size;
    const unsigned char* p;
    unsigned int remaining;
    unsigned int slot;
    unsigned int i;

    if (out_chars == (const unsigned short**)0 || out_len == (unsigned int*)0)
        return 0;

    type.by_name = 0;
    type.id = DUET_RES_TYPE_STRING;
    type.name = (const unsigned short*)0;
    type.name_len = 0u;

    name.by_name = 0;
    name.id = (string_id >> 4) + 1u;
    name.name = (const unsigned short*)0;
    name.name_len = 0u;

    if (!duet_res_find(view, &type, &name, lang, want_lang, &rva, &size))
        return 0;
    p = duet_res_at(view, rva, size);
    if (p == (const unsigned char*)0)
        return 0;

    slot = string_id & 15u;
    remaining = size;
    for (i = 0; i <= slot; ++i)
    {
        unsigned int chars;
        unsigned int bytes;
        if (remaining < 2u)
            return 0; /* bundle truncated before the slot — not found */
        chars = duet_res_u16(p);
        p += 2u;
        remaining -= 2u;
        if (chars > remaining / 2u)
            return 0;
        bytes = chars * 2u;
        if (i == slot)
        {
            if (chars == 0u)
                return 0; /* unused slot */
            *out_chars = (const unsigned short*)(const void*)p;
            *out_len = chars;
            return 1;
        }
        p += bytes;
        remaining -= bytes;
    }
    return 0;
}

/* ---- Icon / cursor resource decoding ----
 *
 * RT_GROUP_ICON (14) contains a 6-byte header + N GRPICONDIRENTRY
 * records, each 14 bytes:
 *   u8  bWidth, bHeight (0 means 256)
 *   u8  bColorCount, bReserved
 *   u16 wPlanes, wBitCount
 *   u32 dwBytesInRes
 *   u16 nID              <-- RT_ICON resource integer ID
 *
 * RT_ICON (3) contains a BITMAPINFOHEADER (40 bytes minimum) followed
 * by the XOR colour rows (bottom-up DIB) and then the 1bpp AND mask
 * rows (also bottom-up, DWORD-aligned).
 *
 * RT_GROUP_CURSOR (12) / RT_CURSOR (1) use the same layout but the
 * GRPCURSORDIRENTRY swaps planes/bitCount for xHotspot/yHotspot, and
 * the RT_CURSOR body prepends a 4-byte hotspot header before the
 * BITMAPINFOHEADER.
 *
 * Provenance: PE/COFF spec section 6.9, MSDN NEWHEADER / RESDIR /
 * CURSORDIR documentation. Added 2026-07-29. */

#define DUET_RES_GRPICON_HEADER_SIZE 6u
#define DUET_RES_GRPICON_ENTRY_SIZE 14u

/* Select the best icon size from an RT_GROUP_ICON resource.
 *
 * Walks the group directory, picks the entry whose dimensions best
 * match `desired_w x desired_h`, and writes the chosen RT_ICON integer
 * ID into `*out_icon_id`. Returns 1 on hit, 0 if the group is empty
 * or malformed.
 *
 * `name_key` is the level-2 key, so the group may be named either by an
 * integer ordinal or by a UTF-16 string (`.rc` `MYICON ICON "x.ico"`).
 * The level-1 type stays an integer because RT_GROUP_ICON /
 * RT_GROUP_CURSOR are fixed ordinals, and the RT_ICON members the group
 * points at are always integer nIDs by format definition.
 *
 * Selection heuristic: prefer exact match, then the next larger, then
 * the largest available. Ties break on higher bit depth. */
DUET_RES_INLINE int duet_res_pick_icon_key(const DUET_RES_VIEW* view, unsigned int type_id,
                                           const DUET_RES_KEY* name_key, unsigned int desired_w, unsigned int desired_h,
                                           unsigned int* out_icon_id, unsigned int* out_width, unsigned int* out_height)
{
    DUET_RES_KEY type;
    unsigned int rva;
    unsigned int size;
    const unsigned char* data;
    unsigned int count;
    unsigned int i;
    int best_score;
    unsigned int best_id;
    unsigned int best_w;
    unsigned int best_h;

    if (out_icon_id == (unsigned int*)0 || name_key == (const DUET_RES_KEY*)0)
        return 0;

    type = duet_res_key_id(type_id);

    if (!duet_res_find(view, &type, name_key, 0, 0, &rva, &size))
        return 0;
    data = duet_res_at(view, rva, size);
    if (data == (const unsigned char*)0 || size < DUET_RES_GRPICON_HEADER_SIZE)
        return 0;
    count = duet_res_u16(data + 4u);
    if (count == 0u || size < DUET_RES_GRPICON_HEADER_SIZE + count * DUET_RES_GRPICON_ENTRY_SIZE)
        return 0;

    best_score = -1;
    best_id = 0u;
    best_w = 0u;
    best_h = 0u;
    for (i = 0; i < count; ++i)
    {
        const unsigned char* e = data + DUET_RES_GRPICON_HEADER_SIZE + i * DUET_RES_GRPICON_ENTRY_SIZE;
        unsigned int ew = e[0];
        unsigned int eh = e[1];
        unsigned int bits = duet_res_u16(e + 6u);
        unsigned int eid = duet_res_u16(e + 12u);
        int score;
        if (ew == 0u)
            ew = 256u;
        if (eh == 0u)
            eh = 256u;
        /* Score: exact = 1000000, larger = 500000 - delta, smaller = delta. */
        if (ew == desired_w && eh == desired_h)
            score = 1000000 + (int)bits;
        else if (ew >= desired_w && eh >= desired_h)
            score = 500000 - (int)(ew - desired_w + eh - desired_h) + (int)bits;
        else
            score = (int)(ew + eh + bits);
        if (score > best_score)
        {
            best_score = score;
            best_id = eid;
            best_w = ew;
            best_h = eh;
        }
    }
    if (best_score < 0)
        return 0;
    *out_icon_id = best_id;
    if (out_width != (unsigned int*)0)
        *out_width = best_w;
    if (out_height != (unsigned int*)0)
        *out_height = best_h;
    return 1;
}

/* Integer-ordinal form of duet_res_pick_icon_key. */
DUET_RES_INLINE int duet_res_pick_icon(const DUET_RES_VIEW* view, unsigned int type_id, unsigned int name_id,
                                       unsigned int desired_w, unsigned int desired_h, unsigned int* out_icon_id,
                                       unsigned int* out_width, unsigned int* out_height)
{
    const DUET_RES_KEY name = duet_res_key_id(name_id);
    return duet_res_pick_icon_key(view, type_id, &name, desired_w, desired_h, out_icon_id, out_width, out_height);
}

/* Decode one DIB scanline into BGRA output pixels.
 *
 * `palette` points to the DIB colour table (BGRX quads) and may be NULL
 * when `palette_entries` is 0 (bpp > 8). When `opaque_alpha` is
 * non-zero the output alpha is forced to 255 for every bpp including
 * 32 — RT_BITMAP semantics, where the 4th source byte is padding, not
 * alpha. When zero, 32bpp alpha passes through and lower depths get
 * 255 — RT_ICON semantics, where the AND mask (applied by the caller)
 * carries transparency.
 *
 * The caller has already validated that `row` spans a full stride and
 * that `dst` spans `width * 4` writable bytes. Shared by
 * duet_res_decode_icon and duet_res_decode_bitmap so the per-bpp pixel
 * unpacking lives in exactly one place. */
DUET_RES_INLINE void duet_res_decode_dib_row(const unsigned char* row, const unsigned char* palette,
                                             unsigned int palette_entries, unsigned int bpp, unsigned int width,
                                             int opaque_alpha, unsigned char* dst)
{
    unsigned int x;
    for (x = 0; x < width; ++x)
    {
        unsigned char b = 0, g = 0, r = 0, a = 255;

        if (bpp == 32u)
        {
            b = row[x * 4u];
            g = row[x * 4u + 1u];
            r = row[x * 4u + 2u];
            a = opaque_alpha ? (unsigned char)255 : row[x * 4u + 3u];
        }
        else if (bpp == 24u)
        {
            b = row[x * 3u];
            g = row[x * 3u + 1u];
            r = row[x * 3u + 2u];
        }
        else
        {
            unsigned int idx;
            if (bpp == 8u)
                idx = row[x];
            else if (bpp == 4u)
                idx = ((unsigned int)row[x / 2u] >> (4u * (1u - (x & 1u)))) & 0xFu;
            else /* bpp == 1 */
                idx = ((unsigned int)row[x / 8u] >> (7u - (x & 7u))) & 1u;
            if (idx < palette_entries)
            {
                b = palette[idx * 4u];
                g = palette[idx * 4u + 1u];
                r = palette[idx * 4u + 2u];
            }
        }

        dst[x * 4u + 0u] = b;
        dst[x * 4u + 1u] = g;
        dst[x * 4u + 2u] = r;
        dst[x * 4u + 3u] = a;
    }
}

/* Decode an RT_ICON (or RT_CURSOR) DIB body into caller-provided BGRA
 * pixels. The AND mask (1bpp, bottom-up, DWORD-aligned) sets alpha=0
 * for transparent pixels.
 *
 * `icon_type` selects the resource type for the lookup:
 *   DUET_RES_TYPE_ICON (3)   -- RT_ICON
 *   DUET_RES_TYPE_CURSOR (1) -- RT_CURSOR (body has 4-byte hotspot prefix)
 *
 * `out_bgra` must point to `max_pixels * 4` writable bytes. The caller
 * must know the icon dimensions (from duet_res_pick_icon). On success
 * writes `icon_w * icon_h` BGRA pixels and returns 1.
 *
 * For cursors, the hotspot is written to `*out_x_hot`, `*out_y_hot`
 * if those pointers are non-NULL. */
DUET_RES_INLINE int duet_res_decode_icon(const DUET_RES_VIEW* view, unsigned int icon_type, unsigned int icon_id,
                                         unsigned int icon_w, unsigned int icon_h, unsigned char* out_bgra,
                                         unsigned int max_pixels, unsigned int* out_x_hot, unsigned int* out_y_hot)
{
    DUET_RES_KEY type;
    DUET_RES_KEY name;
    unsigned int rva;
    unsigned int size;
    const unsigned char* body;
    const unsigned char* bih;
    unsigned int bih_size;
    unsigned int bmp_w;
    int bmp_h_raw;
    unsigned int bmp_h;
    unsigned int bpp;
    unsigned int color_table_entries;
    unsigned int color_table_bytes;
    unsigned int xor_stride;
    unsigned int and_stride;
    unsigned int xor_offset;
    unsigned int and_offset;
    unsigned int y;

    if (out_bgra == (unsigned char*)0 || icon_w == 0u || icon_h == 0u)
        return 0;
    if (icon_w * icon_h > max_pixels)
        return 0;

    type.by_name = 0;
    type.id = icon_type;
    type.name = (const unsigned short*)0;
    type.name_len = 0u;
    name.by_name = 0;
    name.id = icon_id;
    name.name = (const unsigned short*)0;
    name.name_len = 0u;

    if (!duet_res_find(view, &type, &name, 0, 0, &rva, &size))
        return 0;
    body = duet_res_at(view, rva, size);
    if (body == (const unsigned char*)0)
        return 0;

    /* RT_CURSOR has a 4-byte hotspot header before the BIH. */
    if (icon_type == DUET_RES_TYPE_CURSOR)
    {
        if (size < 4u)
            return 0;
        if (out_x_hot != (unsigned int*)0)
            *out_x_hot = duet_res_u16(body);
        if (out_y_hot != (unsigned int*)0)
            *out_y_hot = duet_res_u16(body + 2u);
        body += 4u;
        size -= 4u;
    }
    bih = body;
    if (size < 40u)
        return 0;
    bih_size = duet_res_u32(bih);
    if (bih_size < 40u || bih_size > size)
        return 0;

    bmp_w = duet_res_u32(bih + 4u);
    bmp_h_raw = (int)duet_res_u32(bih + 8u);
    /* In an icon, biHeight = XOR height + AND height (both equal to the
     * icon height), so the actual image height is biHeight / 2. */
    if (bmp_h_raw > 0)
        bmp_h = (unsigned int)bmp_h_raw / 2u;
    else
        bmp_h = (unsigned int)(-bmp_h_raw) / 2u;
    bpp = duet_res_u16(bih + 14u);
    if (bmp_w != icon_w || bmp_h != icon_h)
        return 0; /* dimensions don't match what the group claimed */
    if (bpp != 32u && bpp != 24u && bpp != 8u && bpp != 4u && bpp != 1u)
        return 0;

    /* Colour table entries. BI_RGB is the only compression we accept. */
    {
        unsigned int compression = duet_res_u32(bih + 16u);
        unsigned int clr_used = duet_res_u32(bih + 32u);
        if (compression != 0u) /* BI_RGB */
            return 0;
        if (bpp <= 8u)
        {
            color_table_entries = clr_used != 0u ? clr_used : (1u << bpp);
            if (color_table_entries > (1u << bpp))
                color_table_entries = (1u << bpp);
        }
        else
        {
            color_table_entries = 0u;
        }
    }
    color_table_bytes = color_table_entries * 4u;

    /* Scanline strides (DWORD-aligned). */
    xor_stride = ((bmp_w * bpp + 31u) / 32u) * 4u;
    and_stride = ((bmp_w + 31u) / 32u) * 4u;

    xor_offset = bih_size + color_table_bytes;
    and_offset = xor_offset + xor_stride * bmp_h;

    if (and_offset + and_stride * bmp_h > size)
        return 0; /* truncated */

    /* Decode rows bottom-up. DIB row 0 is the bottom of the image. */
    for (y = 0; y < bmp_h; ++y)
    {
        const unsigned int dst_y = bmp_h - 1u - y; /* flip to top-down */
        unsigned char* dst_row = out_bgra + dst_y * bmp_w * 4u;
        const unsigned char* xor_row = bih + xor_offset + y * xor_stride;
        const unsigned char* and_row = bih + and_offset + y * and_stride;
        const unsigned char* palette = bih + bih_size;
        unsigned int x;

        /* Decode colour from the XOR bitmap (32bpp alpha passes through). */
        duet_res_decode_dib_row(xor_row, palette, color_table_entries, bpp, bmp_w, 0, dst_row);

        /* AND mask: bit=1 means transparent. For 32bpp icons with
         * per-pixel alpha, the AND mask is usually all zeros and the
         * alpha channel carries transparency; we honour both. */
        for (x = 0; x < bmp_w; ++x)
        {
            const unsigned int and_bit = ((unsigned int)and_row[x / 8u] >> (7u - (x & 7u))) & 1u;
            if (and_bit)
                dst_row[x * 4u + 3u] = 0;
        }
    }
    return 1;
}

/* ---- RT_BITMAP resource decoding ----
 *
 * RT_BITMAP (2) contains a packed DIB: a BITMAPINFOHEADER (>= 40
 * bytes), then the colour table (bpp <= 8 only, BGRX quads), then the
 * pixel rows (DWORD-aligned strides) — exactly a `.bmp` file with the
 * 14-byte BITMAPFILEHEADER stripped, which is what the resource
 * compiler stores. Unlike RT_ICON there is no AND mask and biHeight is
 * the real pixel height: positive = bottom-up rows, negative =
 * top-down rows.
 *
 * Provenance: MSDN LoadBitmap / BITMAPINFOHEADER documentation.
 * Added 2026-08-05 for the RT_BITMAP decode slice. */

/* Dimension bound applied to both axes before any stride math. Keeps
 * every intermediate product comfortably inside u32 (16384 * 32bpp
 * stride and 16384 rows are each < 2^20) so a hostile header cannot
 * wrap the truncation check. */
#define DUET_RES_BITMAP_MAX_DIM 16384u

/* Internal: locate + validate the RT_BITMAP body named by `name_key`
 * (integer ordinal or UTF-16 string). On success writes the body
 * pointer, the parsed geometry and the colour-table entry count; the
 * body has already been proven to hold the header, the colour table and
 * every pixel row. Fails closed (returns 0) on any malformed or
 * unsupported header. */
DUET_RES_INLINE int duet_res_bitmap_locate(const DUET_RES_VIEW* view, const DUET_RES_KEY* name_key,
                                           const unsigned char** out_body, unsigned int* out_header_bytes,
                                           unsigned int* out_w, unsigned int* out_h, int* out_top_down,
                                           unsigned int* out_bpp, unsigned int* out_palette_entries)
{
    DUET_RES_KEY type;
    unsigned int rva;
    unsigned int size;
    const unsigned char* body;
    unsigned int bih_size;
    unsigned int bmp_w;
    int bmp_h_raw;
    unsigned int bmp_h;
    unsigned int bpp;
    unsigned int palette_entries;
    unsigned int stride;
    unsigned long long needed;

    if (name_key == (const DUET_RES_KEY*)0)
        return 0;
    type = duet_res_key_id(DUET_RES_TYPE_BITMAP);

    if (!duet_res_find(view, &type, name_key, 0, 0, &rva, &size))
        return 0;
    body = duet_res_at(view, rva, size);
    if (body == (const unsigned char*)0 || size < 40u)
        return 0;

    bih_size = duet_res_u32(body);
    if (bih_size < 40u || bih_size > size)
        return 0;

    bmp_w = duet_res_u32(body + 4u);
    bmp_h_raw = (int)duet_res_u32(body + 8u);
    bmp_h = bmp_h_raw < 0 ? (unsigned int)(-(long long)bmp_h_raw) : (unsigned int)bmp_h_raw;
    bpp = duet_res_u16(body + 14u);
    if (bmp_w == 0u || bmp_h == 0u || bmp_w > DUET_RES_BITMAP_MAX_DIM || bmp_h > DUET_RES_BITMAP_MAX_DIM)
        return 0;
    if (bpp != 32u && bpp != 24u && bpp != 8u && bpp != 4u && bpp != 1u)
        return 0;
    if (duet_res_u32(body + 16u) != 0u) /* BI_RGB only */
        return 0;

    if (bpp <= 8u)
    {
        const unsigned int clr_used = duet_res_u32(body + 32u);
        palette_entries = clr_used != 0u ? clr_used : (1u << bpp);
        if (palette_entries > (1u << bpp))
            palette_entries = (1u << bpp);
    }
    else
    {
        palette_entries = 0u;
    }

    stride = ((bmp_w * bpp + 31u) / 32u) * 4u;
    needed = (unsigned long long)bih_size + (unsigned long long)palette_entries * 4u +
             (unsigned long long)stride * (unsigned long long)bmp_h;
    if (needed > (unsigned long long)size)
        return 0; /* truncated */

    if (out_body != (const unsigned char**)0)
        *out_body = body;
    if (out_header_bytes != (unsigned int*)0)
        *out_header_bytes = bih_size;
    if (out_w != (unsigned int*)0)
        *out_w = bmp_w;
    if (out_h != (unsigned int*)0)
        *out_h = bmp_h;
    if (out_top_down != (int*)0)
        *out_top_down = bmp_h_raw < 0;
    if (out_bpp != (unsigned int*)0)
        *out_bpp = bpp;
    if (out_palette_entries != (unsigned int*)0)
        *out_palette_entries = palette_entries;
    return 1;
}

/* Query an RT_BITMAP resource's geometry without decoding it, so a
 * caller can size its pixel buffer first. Returns 1 on hit. */
DUET_RES_INLINE int duet_res_bitmap_info_key(const DUET_RES_VIEW* view, const DUET_RES_KEY* name_key,
                                             unsigned int* out_w, unsigned int* out_h, unsigned int* out_bpp)
{
    return duet_res_bitmap_locate(view, name_key, (const unsigned char**)0, (unsigned int*)0, out_w, out_h, (int*)0,
                                  out_bpp, (unsigned int*)0);
}

/* Integer-ordinal form of duet_res_bitmap_info_key. */
DUET_RES_INLINE int duet_res_bitmap_info(const DUET_RES_VIEW* view, unsigned int bitmap_id, unsigned int* out_w,
                                         unsigned int* out_h, unsigned int* out_bpp)
{
    const DUET_RES_KEY name = duet_res_key_id(bitmap_id);
    return duet_res_bitmap_info_key(view, &name, out_w, out_h, out_bpp);
}

/* Decode the RT_BITMAP named by `name_key` (integer ordinal or UTF-16
 * string) into caller-provided top-down BGRA pixels. `out_bgra` must
 * point to `max_pixels * 4` writable bytes; the decode is refused (0)
 * when `w * h > max_pixels`. Output alpha is always 255 — GDI treats a
 * DIB's 4th byte as padding, so a bitmap authored with zeroed pad bytes
 * must not come out invisible on an alpha-honouring compositor. On
 * success writes the dimensions to `*out_w` / `*out_h` (when non-NULL)
 * and returns 1. */
DUET_RES_INLINE int duet_res_decode_bitmap_key(const DUET_RES_VIEW* view, const DUET_RES_KEY* name_key,
                                               unsigned char* out_bgra, unsigned int max_pixels, unsigned int* out_w,
                                               unsigned int* out_h)
{
    const unsigned char* body;
    unsigned int header_bytes;
    unsigned int bmp_w;
    unsigned int bmp_h;
    int top_down;
    unsigned int bpp;
    unsigned int palette_entries;
    unsigned int stride;
    const unsigned char* palette;
    const unsigned char* pixels;
    unsigned int y;

    if (out_bgra == (unsigned char*)0)
        return 0;
    if (!duet_res_bitmap_locate(view, name_key, &body, &header_bytes, &bmp_w, &bmp_h, &top_down, &bpp,
                                &palette_entries))
        return 0;
    if ((unsigned long long)bmp_w * (unsigned long long)bmp_h > (unsigned long long)max_pixels)
        return 0;

    stride = ((bmp_w * bpp + 31u) / 32u) * 4u;
    palette = body + header_bytes;
    pixels = palette + palette_entries * 4u;

    for (y = 0; y < bmp_h; ++y)
    {
        const unsigned int dst_y = top_down ? y : bmp_h - 1u - y;
        duet_res_decode_dib_row(pixels + y * stride, palette, palette_entries, bpp, bmp_w, 1,
                                out_bgra + dst_y * bmp_w * 4u);
    }
    if (out_w != (unsigned int*)0)
        *out_w = bmp_w;
    if (out_h != (unsigned int*)0)
        *out_h = bmp_h;
    return 1;
}

/* Integer-ordinal form of duet_res_decode_bitmap_key. */
DUET_RES_INLINE int duet_res_decode_bitmap(const DUET_RES_VIEW* view, unsigned int bitmap_id, unsigned char* out_bgra,
                                           unsigned int max_pixels, unsigned int* out_w, unsigned int* out_h)
{
    const DUET_RES_KEY name = duet_res_key_id(bitmap_id);
    return duet_res_decode_bitmap_key(view, &name, out_bgra, max_pixels, out_w, out_h);
}

#endif /* DUETOS_USERLAND_PE_RESOURCES_H */
