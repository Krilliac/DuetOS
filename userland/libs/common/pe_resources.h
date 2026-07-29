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

#endif /* DUETOS_USERLAND_PE_RESOURCES_H */
