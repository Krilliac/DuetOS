// test_manifest.cpp — hosted unit test for the Win32 SxS assembly-
// manifest parser (kernel/loader/manifest.h + manifest.cpp).
//
// Covers:
//   - ParseManifestXml: execution level, DPI awareness, long-path
//     awareness, SxS dependency extraction, edge cases (empty,
//     malformed, missing elements).
//   - ParseManifestFromPe: synthetic PE with an embedded RT_MANIFEST
//     resource — verifies end-to-end extraction from raw PE bytes.
//
// Expected behaviour is pinned to the MSDN "Application Manifests"
// documentation and the DPI awareness APIs.

#include "host_test_helper.h"

// The manifest parser is a freestanding kernel TU — include it by
// relative path so the host test compiles without kernel infra.
#include "../../kernel/loader/manifest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace duetos_host_test;
using duetos::core::ManifestInfo;
using duetos::core::ParseManifestFromPe;
using duetos::core::ParseManifestXml;

// Helper: parse a C string as manifest XML.
static ManifestInfo parse(const char* xml)
{
    return ParseManifestXml(reinterpret_cast<const uint8_t*>(xml), std::strlen(xml));
}

// ---------------------------------------------------------------
// ParseManifestXml tests
// ---------------------------------------------------------------

static void test_empty_input()
{
    ManifestInfo info = ParseManifestXml(nullptr, 0);
    EXPECT_FALSE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level), static_cast<int>(ManifestInfo::ExecutionLevel::AsInvoker));
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::Unaware));

    info = ParseManifestXml(reinterpret_cast<const uint8_t*>(""), 0);
    EXPECT_FALSE(info.has_manifest);
}

static void test_no_assembly_tag()
{
    // XML that isn't an assembly manifest.
    ManifestInfo info = parse("<root><child/></root>");
    EXPECT_FALSE(info.has_manifest);
}

static void test_minimal_manifest()
{
    const char* xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                      "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "  <assemblyIdentity type=\"win32\" name=\"TestApp\" version=\"1.0.0.0\"/>"
                      "</assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level), static_cast<int>(ManifestInfo::ExecutionLevel::AsInvoker));
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::Unaware));
    EXPECT_FALSE(info.ui_access);
    EXPECT_FALSE(info.long_path_aware);
    EXPECT_EQ(info.sxs_dep_count, 0u);
}

static void test_execution_level_as_invoker()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>"
                      "<requestedPrivileges>"
                      "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>"
                      "</requestedPrivileges></security></trustInfo></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level), static_cast<int>(ManifestInfo::ExecutionLevel::AsInvoker));
    EXPECT_FALSE(info.ui_access);
}

static void test_execution_level_highest_available()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>"
                      "<requestedPrivileges>"
                      "<requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"true\"/>"
                      "</requestedPrivileges></security></trustInfo></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level), static_cast<int>(ManifestInfo::ExecutionLevel::HighestAvailable));
    EXPECT_TRUE(info.ui_access);
}

static void test_execution_level_require_admin()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>"
                      "<requestedPrivileges>"
                      "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>"
                      "</requestedPrivileges></security></trustInfo></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level),
              static_cast<int>(ManifestInfo::ExecutionLevel::RequireAdministrator));
}

static void test_dpi_aware_true()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::SystemAware));
}

static void test_dpi_aware_true_pm()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/PM</dpiAware>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::PerMonitorAware));
}

static void test_dpi_awareness_per_monitor_v2()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "PerMonitorV2</dpiAwareness>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::PerMonitorV2));
}

static void test_dpi_awareness_overrides_dpi_aware()
{
    // When both <dpiAwareness> and <dpiAware> are present,
    // <dpiAwareness> takes precedence.
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
                      "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "PerMonitorV2</dpiAwareness>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::PerMonitorV2));
}

static void test_dpi_awareness_system()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "system</dpiAwareness>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::SystemAware));
}

static void test_long_path_aware()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "true</longPathAware>"
                      "</windowsSettings></application></assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_TRUE(info.long_path_aware);
}

static void test_sxs_dependencies()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<dependency><dependentAssembly>"
                      "<assemblyIdentity type=\"win32\" "
                      "name=\"Microsoft.Windows.Common-Controls\" "
                      "version=\"6.0.0.0\" processorArchitecture=\"*\" "
                      "publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/>"
                      "</dependentAssembly></dependency>"
                      "<dependency><dependentAssembly>"
                      "<assemblyIdentity type=\"win32\" "
                      "name=\"Microsoft.VC90.CRT\" "
                      "version=\"9.0.21022.8\" processorArchitecture=\"amd64\"/>"
                      "</dependentAssembly></dependency>"
                      "</assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(info.sxs_dep_count, 2u);
    EXPECT_STREQ(info.sxs_deps[0], "Microsoft.Windows.Common-Controls");
    EXPECT_STREQ(info.sxs_deps[1], "Microsoft.VC90.CRT");
}

static void test_full_manifest()
{
    // A realistic manifest with all fields.
    const char* xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
                      "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
                      "  <assemblyIdentity type=\"win32\" name=\"RealApp\" version=\"2.0.0.0\"/>\n"
                      "  <dependency><dependentAssembly>\n"
                      "    <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"\n"
                      "      version=\"6.0.0.0\" processorArchitecture=\"*\"\n"
                      "      publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/>\n"
                      "  </dependentAssembly></dependency>\n"
                      "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
                      "    <security><requestedPrivileges>\n"
                      "      <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"true\"/>\n"
                      "    </requestedPrivileges></security>\n"
                      "  </trustInfo>\n"
                      "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
                      "    <windowsSettings>\n"
                      "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">"
                      "true</dpiAware>\n"
                      "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "PerMonitorV2</dpiAwareness>\n"
                      "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "true</longPathAware>\n"
                      "    </windowsSettings>\n"
                      "  </application>\n"
                      "</assembly>";
    ManifestInfo info = parse(xml);
    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level),
              static_cast<int>(ManifestInfo::ExecutionLevel::RequireAdministrator));
    EXPECT_TRUE(info.ui_access);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::PerMonitorV2));
    EXPECT_TRUE(info.long_path_aware);
    EXPECT_EQ(info.sxs_dep_count, 1u);
    EXPECT_STREQ(info.sxs_deps[0], "Microsoft.Windows.Common-Controls");
}

// ---------------------------------------------------------------
// ParseManifestFromPe tests — synthetic PE with RT_MANIFEST
// ---------------------------------------------------------------

namespace
{

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v)
{
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v)
{
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    b[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// Build a minimal PE32+ with one .rsrc section containing an
// RT_MANIFEST resource. The manifest XML is placed at the end
// of the resource section.
std::vector<uint8_t> make_pe_with_manifest(const char* manifest_xml)
{
    const size_t xml_len = std::strlen(manifest_xml);

    // Layout:
    //   0x0000 - 0x01FF  DOS header + PE headers + section table
    //   0x0200 - 0x03FF  .rsrc section (resource directory + data)
    // Total image: 0x0400 bytes minimum, extended if XML is large.
    const size_t rsrc_rva = 0x1000; // Virtual address of .rsrc
    const size_t headers_raw = 0x200;

    // Resource directory layout within the section:
    //   0x00: Type directory (1 entry: RT_MANIFEST = 24)
    //   0x18: Name directory for RT_MANIFEST (1 entry: ID 1)
    //   0x30: Language directory for ID 1 (1 entry: LANGID 0)
    //   0x48: Data entry (OffsetToData RVA, Size, CodePage, Reserved)
    //   0x58: XML payload starts here
    const size_t type_dir = 0;
    const size_t name_dir = 0x18;
    const size_t lang_dir = 0x30;
    const size_t data_entry = 0x48;
    const size_t xml_start = 0x58;
    const size_t rsrc_size = xml_start + xml_len;
    const size_t rsrc_raw_size = (rsrc_size + 0x1FF) & ~size_t(0x1FF); // align to 512

    std::vector<uint8_t> pe(headers_raw + rsrc_raw_size, 0);

    // DOS header
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3C, 0x80); // e_lfanew

    // PE signature
    pe[0x80] = 'P';
    pe[0x81] = 'E';

    // COFF header at 0x84
    put16(pe, 0x84, 0x8664); // Machine = AMD64
    put16(pe, 0x86, 1);      // NumberOfSections = 1
    // SizeOfOptionalHeader must be large enough to cover the
    // PE32+ standard/NT-specific fields (112 bytes) plus 16
    // data directory entries (128 bytes) = 240 = 0xF0.
    put16(pe, 0x94, 0xF0); // SizeOfOptionalHeader (240 bytes)

    // Optional header at 0x98
    const size_t opt_base = 0x98;
    put16(pe, opt_base, 0x20B);    // Magic = PE32+
    put32(pe, opt_base + 108, 16); // NumberOfRvaAndSizes = 16
    // Data directory [2] = resource directory.
    // Data dirs start at offset 112 in the PE32+ opt header.
    const size_t dd2 = opt_base + 112 + 2 * 8;
    put32(pe, dd2, static_cast<uint32_t>(rsrc_rva));
    put32(pe, dd2 + 4, static_cast<uint32_t>(rsrc_size));

    // Section table starts at opt_base + SizeOfOptionalHeader.
    const size_t sec = opt_base + 0xF0; // = 0x188
    // Name: ".rsrc\0\0\0"
    pe[sec] = '.';
    pe[sec + 1] = 'r';
    pe[sec + 2] = 's';
    pe[sec + 3] = 'r';
    pe[sec + 4] = 'c';
    put32(pe, sec + 8, static_cast<uint32_t>(rsrc_size));      // VirtualSize
    put32(pe, sec + 12, static_cast<uint32_t>(rsrc_rva));      // VirtualAddress
    put32(pe, sec + 16, static_cast<uint32_t>(rsrc_raw_size)); // SizeOfRawData
    put32(pe, sec + 20, static_cast<uint32_t>(headers_raw));   // PointerToRawData

    // Resource directory (within .rsrc raw data, starting at headers_raw)
    const size_t rb = headers_raw; // rsrc base in file

    // Type directory: 0 named, 1 ID entry (RT_MANIFEST = 24)
    put16(pe, rb + type_dir + 12, 0); // NumberOfNamedEntries
    put16(pe, rb + type_dir + 14, 1); // NumberOfIdEntries
    // Entry: ID = 24, offset = name_dir | 0x80000000
    put32(pe, rb + type_dir + 16, 24);
    put32(pe, rb + type_dir + 20, static_cast<uint32_t>(name_dir) | 0x80000000u);

    // Name directory: 0 named, 1 ID entry (ID 1 = exe manifest)
    put16(pe, rb + name_dir + 12, 0);
    put16(pe, rb + name_dir + 14, 1);
    put32(pe, rb + name_dir + 16, 1); // ID = 1
    put32(pe, rb + name_dir + 20, static_cast<uint32_t>(lang_dir) | 0x80000000u);

    // Language directory: 0 named, 1 ID entry (LANGID 0)
    put16(pe, rb + lang_dir + 12, 0);
    put16(pe, rb + lang_dir + 14, 1);
    put32(pe, rb + lang_dir + 16, 0);                                 // LANGID = 0
    put32(pe, rb + lang_dir + 20, static_cast<uint32_t>(data_entry)); // no high bit = data entry

    // Data entry: OffsetToData (RVA), Size, CodePage, Reserved
    put32(pe, rb + data_entry + 0, static_cast<uint32_t>(rsrc_rva + xml_start)); // RVA of XML
    put32(pe, rb + data_entry + 4, static_cast<uint32_t>(xml_len));
    put32(pe, rb + data_entry + 8, 0);  // CodePage
    put32(pe, rb + data_entry + 12, 0); // Reserved

    // Copy XML payload
    std::memcpy(pe.data() + rb + xml_start, manifest_xml, xml_len);

    return pe;
}

} // anonymous namespace

static void test_pe_manifest_extraction()
{
    const char* xml = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
                      "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>"
                      "<requestedPrivileges>"
                      "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>"
                      "</requestedPrivileges></security></trustInfo>"
                      "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>"
                      "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "PerMonitorV2</dpiAwareness>"
                      "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
                      "true</longPathAware>"
                      "</windowsSettings></application></assembly>";

    std::vector<uint8_t> pe = make_pe_with_manifest(xml);
    ManifestInfo info = ParseManifestFromPe(pe.data(), pe.size());

    EXPECT_TRUE(info.has_manifest);
    EXPECT_EQ(static_cast<int>(info.execution_level),
              static_cast<int>(ManifestInfo::ExecutionLevel::RequireAdministrator));
    EXPECT_FALSE(info.ui_access);
    EXPECT_EQ(static_cast<int>(info.dpi_awareness), static_cast<int>(ManifestInfo::DpiAwareness::PerMonitorV2));
    EXPECT_TRUE(info.long_path_aware);
}

static void test_pe_no_resource_dir()
{
    // Minimal PE with no resource directory.
    std::vector<uint8_t> pe(512, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3C, 0x80);
    pe[0x80] = 'P';
    pe[0x81] = 'E';
    put16(pe, 0x84, 0x8664);
    put16(pe, 0x86, 0); // 0 sections
    put16(pe, 0x94, 0x70);
    put16(pe, 0x98, 0x20B);
    put32(pe, 0x98 + 108, 2); // only 2 data dirs (no resource dir)

    ManifestInfo info = ParseManifestFromPe(pe.data(), pe.size());
    EXPECT_FALSE(info.has_manifest);
}

static void test_pe_truncated()
{
    ManifestInfo info = ParseManifestFromPe(nullptr, 0);
    EXPECT_FALSE(info.has_manifest);

    uint8_t tiny[4] = {'M', 'Z', 0, 0};
    info = ParseManifestFromPe(tiny, sizeof(tiny));
    EXPECT_FALSE(info.has_manifest);
}

// ---------------------------------------------------------------
// main
// ---------------------------------------------------------------

int main()
{
    test_empty_input();
    test_no_assembly_tag();
    test_minimal_manifest();
    test_execution_level_as_invoker();
    test_execution_level_highest_available();
    test_execution_level_require_admin();
    test_dpi_aware_true();
    test_dpi_aware_true_pm();
    test_dpi_awareness_per_monitor_v2();
    test_dpi_awareness_overrides_dpi_aware();
    test_dpi_awareness_system();
    test_long_path_aware();
    test_sxs_dependencies();
    test_full_manifest();
    test_pe_manifest_extraction();
    test_pe_no_resource_dir();
    test_pe_truncated();

    return finish_main("manifest");
}
