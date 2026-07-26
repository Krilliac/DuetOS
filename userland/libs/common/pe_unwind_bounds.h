#ifndef DUETOS_USERLAND_PE_UNWIND_BOUNDS_H
#define DUETOS_USERLAND_PE_UNWIND_BOUNDS_H

/*
 * Bounded PE32+ view used by the user-mode x64 unwinders.
 *
 * Module bases come from the kernel loader, which guarantees that the
 * first image page is mapped.  Until the kernel exposes its authoritative
 * mapped image length to user mode, the parser keeps the initial DOS/NT
 * header probe inside that first 4 KiB page, then treats the validated
 * SizeOfImage as the bound for all subsequent RVA arithmetic.
 */

#define DUET_PE_HEADER_PROBE 0x1000u
#define DUET_PE_SCN_MEM_EXECUTE 0x20000000u

#if defined(__clang__) || defined(__GNUC__)
#define DUET_PE_INLINE static inline __attribute__((unused))
#else
#define DUET_PE_INLINE static inline
#endif

typedef struct
{
    const unsigned char* base;
    unsigned int size;
    unsigned int headers_size;
    unsigned int pdata_rva;
    unsigned int pdata_size;
    unsigned int sections_rva;
    unsigned int section_count;
} DUET_PE_VIEW;

typedef struct
{
    const unsigned char* ui;
    const unsigned short* codes;
    const unsigned char* tail;
    unsigned int flags;
    unsigned int count;
    unsigned int frreg;
    unsigned int froff;
} DUET_PE_UNWIND_LAYOUT;

DUET_PE_INLINE unsigned short duet_pe_u16(const void* p)
{
    const unsigned char* b = (const unsigned char*)p;
    return (unsigned short)((unsigned short)b[0] | (unsigned short)((unsigned short)b[1] << 8));
}

DUET_PE_INLINE unsigned int duet_pe_u32(const void* p)
{
    const unsigned char* b = (const unsigned char*)p;
    return (unsigned int)b[0] | ((unsigned int)b[1] << 8) | ((unsigned int)b[2] << 16) | ((unsigned int)b[3] << 24);
}

DUET_PE_INLINE int duet_pe_range(unsigned int rva, unsigned int span, unsigned int image_size)
{
    return rva <= image_size && span <= image_size - rva;
}

DUET_PE_INLINE unsigned int duet_pe_section_span(const unsigned char* section)
{
    const unsigned int virtual_size = duet_pe_u32(section + 8u);
    const unsigned int raw_size = duet_pe_u32(section + 16u);
    return virtual_size > raw_size ? virtual_size : raw_size;
}

DUET_PE_INLINE int duet_pe_span_mapped(const DUET_PE_VIEW* view, unsigned int rva, unsigned int span)
{
    if (view == (const DUET_PE_VIEW*)0 || !duet_pe_range(rva, span, view->size))
        return 0;
    if (rva <= view->headers_size && span <= view->headers_size - rva)
        return 1;
    for (unsigned int i = 0; i < view->section_count; ++i)
    {
        const unsigned char* section = view->base + view->sections_rva + i * 40u;
        const unsigned int section_rva = duet_pe_u32(section + 12u);
        const unsigned int section_span = duet_pe_section_span(section);
        if (rva >= section_rva && rva - section_rva <= section_span && span <= section_span - (rva - section_rva))
            return 1;
    }
    return 0;
}

DUET_PE_INLINE int duet_pe_span_executable(const DUET_PE_VIEW* view, unsigned int rva, unsigned int span)
{
    if (view == (const DUET_PE_VIEW*)0 || span == 0u || !duet_pe_range(rva, span, view->size))
        return 0;
    for (unsigned int i = 0; i < view->section_count; ++i)
    {
        const unsigned char* section = view->base + view->sections_rva + i * 40u;
        const unsigned int section_rva = duet_pe_u32(section + 12u);
        const unsigned int section_span = duet_pe_section_span(section);
        const unsigned int characteristics = duet_pe_u32(section + 36u);
        if (rva >= section_rva && rva - section_rva <= section_span && span <= section_span - (rva - section_rva))
            return (characteristics & DUET_PE_SCN_MEM_EXECUTE) != 0u;
    }
    return 0;
}

DUET_PE_INLINE int duet_pe_parse(const void* image_base, DUET_PE_VIEW* out)
{
    if (image_base == (const void*)0 || out == (DUET_PE_VIEW*)0)
        return 0;
    const unsigned char* image = (const unsigned char*)image_base;
    if (image[0] != 'M' || image[1] != 'Z')
        return 0;

    const unsigned int e_lfanew = duet_pe_u32(image + 0x3Cu);
    if (e_lfanew < 0x40u || !duet_pe_range(e_lfanew, 24u, DUET_PE_HEADER_PROBE))
        return 0;
    const unsigned char* nt = image + e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0u || nt[3] != 0u)
        return 0;

    const unsigned int section_count = duet_pe_u16(nt + 6u);
    const unsigned int optional_size = duet_pe_u16(nt + 20u);
    const unsigned int optional_rva = e_lfanew + 24u;
    if (section_count == 0u || optional_size < 0x90u ||
        !duet_pe_range(optional_rva, optional_size, DUET_PE_HEADER_PROBE))
        return 0;
    const unsigned char* optional = image + optional_rva;
    if (duet_pe_u16(optional) != 0x20Bu || duet_pe_u32(optional + 0x6Cu) < 4u)
        return 0;

    const unsigned int image_size = duet_pe_u32(optional + 0x38u);
    const unsigned int headers_size = duet_pe_u32(optional + 0x3Cu);
    const unsigned int sections_rva = optional_rva + optional_size;
    const unsigned long long sections_bytes = (unsigned long long)section_count * 40ULL;
    if (image_size < DUET_PE_HEADER_PROBE || headers_size < sections_rva || headers_size > image_size ||
        sections_rva > DUET_PE_HEADER_PROBE ||
        sections_bytes > (unsigned long long)(DUET_PE_HEADER_PROBE - sections_rva) ||
        sections_bytes > (unsigned long long)(headers_size - sections_rva))
        return 0;
    if ((unsigned long long)image_base + (unsigned long long)image_size < (unsigned long long)image_base)
        return 0;

    const unsigned int pdata_rva = duet_pe_u32(optional + 0x88u);
    const unsigned int pdata_size = duet_pe_u32(optional + 0x8Cu);
    if (pdata_rva == 0u || (pdata_rva & 3u) != 0u || pdata_size < 12u || (pdata_size % 12u) != 0u ||
        !duet_pe_range(pdata_rva, pdata_size, image_size))
        return 0;

    for (unsigned int i = 0; i < section_count; ++i)
    {
        const unsigned char* section = image + sections_rva + i * 40u;
        const unsigned int virtual_rva = duet_pe_u32(section + 12u);
        const unsigned int span = duet_pe_section_span(section);
        if (span != 0u && !duet_pe_range(virtual_rva, span, image_size))
            return 0;
    }

    out->base = image;
    out->size = image_size;
    out->headers_size = headers_size;
    out->pdata_rva = pdata_rva;
    out->pdata_size = pdata_size;
    out->sections_rva = sections_rva;
    out->section_count = section_count;
    if (!duet_pe_span_mapped(out, pdata_rva, pdata_size))
        return 0;

    const unsigned char* pdata = image + pdata_rva;
    const unsigned int function_count = pdata_size / 12u;
    unsigned int previous_end = 0u;
    for (unsigned int i = 0; i < function_count; ++i)
    {
        const unsigned char* function = pdata + i * 12u;
        const unsigned int begin = duet_pe_u32(function);
        const unsigned int end = duet_pe_u32(function + 4u);
        const unsigned int unwind = duet_pe_u32(function + 8u);
        if (begin >= end || end > image_size || !duet_pe_span_executable(out, begin, end - begin) ||
            (unwind & 3u) != 0u || !duet_pe_span_mapped(out, unwind, 4u) || (i != 0u && begin < previous_end))
            return 0;
        previous_end = end;
    }

    return 1;
}

DUET_PE_INLINE int duet_pe_runtime_function_fields(const DUET_PE_VIEW* view, const void* function)
{
    if (view == (const DUET_PE_VIEW*)0 || function == (const void*)0)
        return 0;
    const unsigned char* rf = (const unsigned char*)function;
    const unsigned int begin = duet_pe_u32(rf);
    const unsigned int end = duet_pe_u32(rf + 4u);
    const unsigned int unwind = duet_pe_u32(rf + 8u);
    return begin < end && end <= view->size && duet_pe_span_executable(view, begin, end - begin) &&
           (unwind & 3u) == 0u && duet_pe_span_mapped(view, unwind, 4u);
}

DUET_PE_INLINE int duet_pe_runtime_function_pointer(const DUET_PE_VIEW* view, const void* function)
{
    if (view == (const DUET_PE_VIEW*)0 || function == (const void*)0)
        return 0;
    const unsigned long long base = (unsigned long long)view->base;
    const unsigned long long pointer = (unsigned long long)function;
    const unsigned long long pdata = base + view->pdata_rva;
    if (pointer < pdata || pointer - pdata >= view->pdata_size || ((pointer - pdata) % 12ULL) != 0ULL)
        return 0;
    return duet_pe_runtime_function_fields(view, function);
}

DUET_PE_INLINE int duet_pe_unwind_layout(const DUET_PE_VIEW* view, const void* function, DUET_PE_UNWIND_LAYOUT* out)
{
    if (!duet_pe_runtime_function_fields(view, function) || out == (DUET_PE_UNWIND_LAYOUT*)0)
        return 0;
    const unsigned char* rf = (const unsigned char*)function;
    const unsigned int unwind_rva = duet_pe_u32(rf + 8u);
    const unsigned char* ui = view->base + unwind_rva;
    const unsigned int version = ui[0] & 7u;
    const unsigned int flags = ui[0] >> 3;
    const unsigned int count = ui[2];
    const unsigned int codes_bytes = count * 2u;
    if (version != 1u || (flags & ~7u) != 0u || !duet_pe_range(unwind_rva + 4u, codes_bytes, view->size))
        return 0;
    const unsigned int tail_rva = (unwind_rva + 4u + codes_bytes + 3u) & ~3u;
    const unsigned int tail_bytes = (flags & 4u) != 0u ? 12u : ((flags & 3u) != 0u ? 8u : 0u);
    if (((flags & 4u) != 0u && (flags & 3u) != 0u) || tail_rva < unwind_rva ||
        !duet_pe_range(tail_rva, tail_bytes, view->size) ||
        !duet_pe_span_mapped(view, unwind_rva, tail_rva - unwind_rva + tail_bytes))
        return 0;
    out->ui = ui;
    out->codes = (const unsigned short*)(ui + 4u);
    out->tail = view->base + tail_rva;
    out->flags = flags;
    out->count = count;
    out->frreg = ui[3] & 0x0Fu;
    out->froff = ui[3] >> 4;
    return 1;
}

DUET_PE_INLINE int duet_pe_nonvolatile_gpr(unsigned int reg)
{
    return reg == 3u || reg == 5u || reg == 6u || reg == 7u || reg >= 12u;
}

DUET_PE_INLINE int duet_pe_unwind_op_width(unsigned short code, unsigned int frreg, unsigned int* width)
{
    const unsigned int op = ((unsigned int)code >> 8) & 0x0Fu;
    const unsigned int info = ((unsigned int)code >> 12) & 0x0Fu;
    if (width == (unsigned int*)0)
        return 0;
    if (op == 0u)
    {
        if (!duet_pe_nonvolatile_gpr(info))
            return 0;
        *width = 1u;
    }
    else if (op == 1u)
    {
        if (info > 1u)
            return 0;
        *width = info == 0u ? 2u : 3u;
    }
    else if (op == 2u)
    {
        *width = 1u;
    }
    else if (op == 3u)
    {
        if (info != 0u || frreg == 0u || !duet_pe_nonvolatile_gpr(frreg))
            return 0;
        *width = 1u;
    }
    else if (op == 4u || op == 5u)
    {
        if (!duet_pe_nonvolatile_gpr(info))
            return 0;
        *width = op == 4u ? 2u : 3u;
    }
    else if (op == 8u || op == 9u)
    {
        if (info < 6u)
            return 0;
        *width = op == 8u ? 2u : 3u;
    }
    else if (op == 10u)
    {
        if (info > 1u)
            return 0;
        *width = 1u;
    }
    else
    {
        return 0;
    }
    return 1;
}

DUET_PE_INLINE int duet_pe_validate_unwind_codes(const unsigned short* codes, unsigned int count, unsigned int frreg)
{
    if (codes == (const unsigned short*)0 || (frreg != 0u && !duet_pe_nonvolatile_gpr(frreg)))
        return 0;
    for (unsigned int i = 0; i < count;)
    {
        unsigned int width = 0;
        if (!duet_pe_unwind_op_width(codes[i], frreg, &width) || width > count - i)
            return 0;
        i += width;
    }
    return 1;
}

DUET_PE_INLINE unsigned int duet_pe_prolog_offset(const DUET_PE_UNWIND_LAYOUT* layout, const void* function,
                                                  unsigned long long image_base, unsigned long long control_pc)
{
    if (layout == (const DUET_PE_UNWIND_LAYOUT*)0 || function == (const void*)0)
        return 0u;
    const unsigned long long begin = image_base + duet_pe_u32(function);
    if (control_pc <= begin)
        return 0u;
    const unsigned long long offset = control_pc - begin;
    return offset >= (unsigned long long)layout->ui[1] ? 0xFFu : (unsigned int)offset;
}

DUET_PE_INLINE int duet_pe_frame_established(const DUET_PE_UNWIND_LAYOUT* layout, unsigned int prolog_offset)
{
    if (layout == (const DUET_PE_UNWIND_LAYOUT*)0 || layout->frreg == 0u)
        return 0;
    for (unsigned int i = 0; i < layout->count;)
    {
        unsigned int width = 0;
        if (!duet_pe_unwind_op_width(layout->codes[i], layout->frreg, &width) || width > layout->count - i)
            return 0;
        const unsigned int op = ((unsigned int)layout->codes[i] >> 8) & 0x0Fu;
        const unsigned int code_offset = layout->codes[i] & 0xFFu;
        if (op == 3u && code_offset <= prolog_offset)
            return 1;
        i += width;
    }
    return 0;
}

DUET_PE_INLINE int duet_pe_validate_unwind_chain(const DUET_PE_VIEW* view, const void* first)
{
    if (!duet_pe_runtime_function_pointer(view, first))
        return 0;
    DUET_PE_UNWIND_LAYOUT head;
    if (!duet_pe_unwind_layout(view, first, &head))
        return 0;
    const void* function = first;
    for (unsigned int guard = 0; guard < 32u; ++guard)
    {
        DUET_PE_UNWIND_LAYOUT layout;
        if (!duet_pe_unwind_layout(view, function, &layout) ||
            !duet_pe_validate_unwind_codes(layout.codes, layout.count, layout.frreg) || layout.frreg != head.frreg ||
            layout.froff != head.froff)
            return 0;
        if ((layout.flags & 4u) == 0u)
            return 1;
        function = layout.tail;
        if (!duet_pe_runtime_function_fields(view, function))
            return 0;
    }
    return 0;
}

DUET_PE_INLINE int duet_pe_chain_frame_established(const DUET_PE_VIEW* view, const void* first,
                                                   unsigned long long image_base, unsigned long long control_pc)
{
    const void* function = first;
    for (unsigned int guard = 0; guard < 32u; ++guard)
    {
        DUET_PE_UNWIND_LAYOUT layout;
        if (!duet_pe_unwind_layout(view, function, &layout))
            return 0;
        /* Only the active secondary fragment is partial. Every
         * chained parent/primary prologue completed before it. */
        const unsigned int prolog_offset =
            guard == 0u ? duet_pe_prolog_offset(&layout, function, image_base, control_pc) : 0xFFu;
        if (duet_pe_frame_established(&layout, prolog_offset))
            return 1;
        if ((layout.flags & 4u) == 0u)
            return 0;
        function = layout.tail;
    }
    return 0;
}

DUET_PE_INLINE int duet_pe_rva_executable(const DUET_PE_VIEW* view, unsigned int rva)
{
    return duet_pe_span_executable(view, rva, 1u);
}

#undef DUET_PE_INLINE

#endif
