import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart';

import 'bindings/LIEF_bindings.dart';

class PeBinary {
  final Pe_Binary_t peBinary;
  late String name;
  late PeDosHeader dosHeader;
  late PeHeader header;
  late PeOptionalHeader optionalHeader;
  late List<PeDataDirectory> dataDirectories;
  late List<PeSection> sections;
  late List<PeImport> imports;

  PeBinary({required this.peBinary}) {
    // name
    name = basename(peBinary.name.cast<Utf8>().toDartString());

    // dosHeader
    dosHeader = PeDosHeader(dosHeader: peBinary.dos_header);

    // ntHeader
    header = PeHeader(peHeader: peBinary.header);

    // optionalHeader
    optionalHeader =
        PeOptionalHeader(peOptionalHeader: peBinary.optional_header);

    // dataDirectories
    dataDirectories = <PeDataDirectory>[];
    for (int i = 0; i < optionalHeader.numberofRvaAndSize; i++) {
      dataDirectories.add(
          PeDataDirectory(peDataDirectory: peBinary.data_directories[i][0]));
    }

    // sections
    sections = <PeSection>[];
    for (int i = 0; i < header.numberOfSections; i++) {
      sections.add(PeSection(peSection: peBinary.sections[i][0]));
    }

    // imports
    imports = <PeImport>[];
    for (int i = 0;
        i <
            (dataDirectories[LIEF_PE_DATA_DIRECTORY.LIEF_PE_IMPORT_TABLE].size /
                    0x14 -
                1);
        i++) {
      imports.add(PeImport(peImport: peBinary.imports[i][0]));
    }
  }
}

class PeDosHeader {
  final Pe_DosHeader_t dosHeader;
  late int magic;
  late int usedBytesInTheLastPage;
  late int fileSizeInPages;
  late int numberofRelocation;
  late int headerSizeInParagraphs;
  late int minimumExtraparagraphs;
  late int maximumExtraparagraphs;
  late int initialRelativeSs;
  late int initialSp;
  late int checksum;
  late int initialIp;
  late int initialRelativeCs;
  late int addressofRelocationTable;
  late int overlayNumber;
  late List<int> reserved;
  late int oemId;
  late int oemInfo;
  late List<int> reserved2;
  late int addressofNewExeheader;

  PeDosHeader({required this.dosHeader}) {
    magic = dosHeader.magic;
    usedBytesInTheLastPage = dosHeader.used_bytes_in_the_last_page;
    fileSizeInPages = dosHeader.file_size_in_pages;
    numberofRelocation = dosHeader.numberof_relocation;
    headerSizeInParagraphs = dosHeader.header_size_in_paragraphs;
    minimumExtraparagraphs = dosHeader.minimum_extra_paragraphs;
    maximumExtraparagraphs = dosHeader.maximum_extra_paragraphs;
    initialRelativeSs = dosHeader.initial_relative_ss;
    initialSp = dosHeader.initial_sp;
    checksum = dosHeader.checksum;
    initialIp = dosHeader.initial_ip;
    initialRelativeCs = dosHeader.initial_relative_cs;
    addressofRelocationTable = dosHeader.addressof_relocation_table;
    overlayNumber = dosHeader.overlay_number;
    reserved = List<int>.filled(4, 0, growable: false);
    for (int i = 0; i < 4; i++) {
      reserved[i] = dosHeader.reserved[i];
    }
    oemId = dosHeader.oem_id;
    oemInfo = dosHeader.oem_info;
    reserved2 = List<int>.filled(10, 0, growable: false);
    for (int i = 0; i < 10; i++) {
      reserved2[i] = dosHeader.reserved2[i];
    }
    addressofNewExeheader = dosHeader.addressof_new_exeheader;
  }
}

class PeHeader {
  final Pe_Header_t peHeader;
  late int signature;
  late int machine;
  late int numberOfSections;
  late int timeDateStamp;
  late int pointertoSymbolTable;
  late int numberofSymbols;
  late int sizeofOptionalHeader;
  late int characteristics;

  PeHeader({required this.peHeader}) {
    signature = peHeader.signature[0] |
        peHeader.signature[1] << 8 |
        peHeader.signature[2] << 16 |
        peHeader.signature[3] << 24;
    machine = peHeader.machine;
    numberOfSections = peHeader.numberof_sections;
    timeDateStamp = peHeader.time_date_stamp;
    pointertoSymbolTable = peHeader.pointerto_symbol_table;
    numberofSymbols = peHeader.numberof_symbols;
    sizeofOptionalHeader = peHeader.sizeof_optional_header;
    characteristics = peHeader.characteristics;
  }
}

class PeOptionalHeader {
  final Pe_OptionalHeader_t peOptionalHeader;
  late int magic;
  late int majorLinkerVersion;
  late int minorLinkerVersion;
  late int sizeofCode;
  late int sizeofInitializedData;
  late int sizeofUninitializedData;
  late int addressofEntrypoint;
  late int baseofData;
  late int baseofCode;
  late int imagebase;
  late int sectionAlignment;
  late int fileAlignment;
  late int majorOperatingSystemVersion;
  late int minorOperatingSystemVersion;
  late int majorImageVersion;
  late int minorImageVersion;
  late int majorSubsystemVersion;
  late int minorSubsystemVersion;
  late int win32VersionValue;
  late int sizeofImage;
  late int sizeOFHeaders;
  late int checksum;
  late int subsystem;
  late int dllCharacteristics;
  late int sizeOfStackReverse;
  late int sizeOfStackcommit;
  late int sizeOfHeapReverse;
  late int sizeOfHeapcommit;
  late int loaderFlags;
  late int numberofRvaAndSize;

  PeOptionalHeader({required this.peOptionalHeader}) {
    magic = peOptionalHeader.magic;
    majorLinkerVersion = peOptionalHeader.major_linker_version;
    minorLinkerVersion = peOptionalHeader.minor_linker_version;
    sizeofCode = peOptionalHeader.sizeof_code;
    sizeofInitializedData = peOptionalHeader.sizeof_initialized_data;
    sizeofUninitializedData = peOptionalHeader.sizeof_uninitialized_data;
    addressofEntrypoint = peOptionalHeader.addressof_entrypoint;
    baseofData = peOptionalHeader.baseof_data;
    baseofCode = peOptionalHeader.baseof_code;
    imagebase = peOptionalHeader.imagebase;
    sectionAlignment = peOptionalHeader.section_alignment;
    fileAlignment = peOptionalHeader.file_alignment;
    majorOperatingSystemVersion =
        peOptionalHeader.major_operating_system_version;
    minorOperatingSystemVersion =
        peOptionalHeader.minor_operating_system_version;
    majorImageVersion = peOptionalHeader.major_image_version;
    minorImageVersion = peOptionalHeader.minor_image_version;
    majorSubsystemVersion = peOptionalHeader.major_subsystem_version;
    minorSubsystemVersion = peOptionalHeader.minor_subsystem_version;
    win32VersionValue = peOptionalHeader.win32_version_value;
    sizeofImage = peOptionalHeader.sizeof_image;
    sizeOFHeaders = peOptionalHeader.sizeof_headers;
    checksum = peOptionalHeader.checksum;
    subsystem = peOptionalHeader.subsystem;
    dllCharacteristics = peOptionalHeader.dll_characteristics;
    sizeOfStackReverse = peOptionalHeader.sizeof_stack_reserve;
    sizeOfStackcommit = peOptionalHeader.sizeof_stack_commit;
    sizeOfHeapReverse = peOptionalHeader.sizeof_heap_reserve;
    sizeOfHeapcommit = peOptionalHeader.sizeof_heap_commit;
    loaderFlags = peOptionalHeader.loader_flags;
    numberofRvaAndSize = peOptionalHeader.numberof_rva_and_size;
  }
}

class PeDataDirectory {
  final Pe_DataDirectory_t peDataDirectory;
  late int rva;
  late int size;

  PeDataDirectory({required this.peDataDirectory}) {
    rva = peDataDirectory.rva;
    size = peDataDirectory.size;
  }
}

class PeSection {
  final Pe_Section_t peSection;
  late String name;
  late int virtualAddress;
  late int size;
  late int offset;
  late int virtualSize;
  late int pointertoRelocation;
  late int pointertoLineNumbers;
  late int characteristics;
  late int contentSize;
  // TODO: content
  late double entropy;

  PeSection({required this.peSection}) {
    name = peSection.name.cast<Utf8>().toDartString();
    virtualAddress = peSection.virtual_address;
    size = peSection.size;
    offset = peSection.offset;
    virtualSize = peSection.virtual_size;
    pointertoRelocation = peSection.pointerto_relocation;
    pointertoLineNumbers = peSection.pointerto_line_numbers;
    characteristics = peSection.characteristics;
    // content
    contentSize = peSection.content_size;
    entropy = peSection.entropy;
  }
}

class PeImport {
  final Pe_Import_t peImport;
  late String name;
  late int forwarderChain;
  late int timeDateStamp;
  late List<PeImportEntry> entries;
  late int importAddressTableRva;
  late int importLookupTableRva;

  PeImport({required this.peImport}) {
    name = peImport.name.cast<Utf8>().toDartString();
    forwarderChain = peImport.forwarder_chain;
    timeDateStamp = peImport.timedatestamp;
    entries = <PeImportEntry>[];
    for (int i = 0; peImport.entries[i].address != 0; i++) {
      entries.add(PeImportEntry(peImportEntry: peImport.entries[i][0]));
    }
    importAddressTableRva = peImport.import_address_table_rva;
    importLookupTableRva = peImport.import_lookup_table_rva;
  }
}

class PeImportEntry {
  final Pe_ImportEntry_t peImportEntry;
  late int isOrdinal;
  late String name;
  late int ordinal;
  late int hintNameRva;
  late int hint;
  late int iatValue;
  late int data;
  late int iatAddress;

  PeImportEntry({required this.peImportEntry}) {
    isOrdinal = peImportEntry.is_ordinal;
    name = peImportEntry.name.cast<Utf8>().toDartString();
    ordinal = peImportEntry.ordinal;
    hintNameRva = peImportEntry.hint_name_rva;
    hint = peImportEntry.hint;
    iatValue = peImportEntry.iat_value;
    data = peImportEntry.data;
    iatAddress = peImportEntry.iat_address;
  }
}
