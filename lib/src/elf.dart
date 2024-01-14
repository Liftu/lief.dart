import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart';

import 'bindings/LIEF_bindings.dart';

class ElfBinary {
  final Elf_Binary_t elfBinary;
  late String name;
  late String interpreter;
  late int type;
  late ElfHeader header;
  late List<ElfSection> sections;
  late List<ElfSegment> segments;
  late List<ElfDynamicEntry> dynamicEntries;
  late List<ElfSymbol> dynamicSymbols;
  late List<ElfSymbol> staticSymbols;

  ElfBinary({required this.elfBinary}) {
    // name
    name = basename(elfBinary.name.cast<Utf8>().toDartString());

    // interpreter
    interpreter = "";
    if (elfBinary.interpreter.address != 0) {
      interpreter = elfBinary.interpreter.cast<Utf8>().toDartString();
    }

    // type
    type = elfBinary.type;

    // header
    header = ElfHeader(elfHeader: elfBinary.header);

    // sections
    sections = <ElfSection>[];
    for (int i = 0; i < header.numberofSections; i++) {
      sections.add(ElfSection(elfSection: elfBinary.sections[i][0]));
    }

    // segments
    segments = <ElfSegment>[];
    for (int i = 0; i < header.numberofSegments; i++) {
      segments.add(ElfSegment(elfSegment: elfBinary.segments[i][0]));
    }

    // dynamicEntries
    dynamicEntries = <ElfDynamicEntry>[];
    for (int i = 0; elfBinary.dynamic_entries[i].address != 0; i++) {
      dynamicEntries.add(
          ElfDynamicEntry(elfDynamicEntry: elfBinary.dynamic_entries[i][0]));
    }

    // dynamicSymbols
    dynamicSymbols = <ElfSymbol>[];
    for (int i = 0; elfBinary.dynamic_symbols[i].address != 0; i++) {
      dynamicSymbols.add(ElfSymbol(elfSymbol: elfBinary.dynamic_symbols[i][0]));
    }

    // staticSymbols
    staticSymbols = <ElfSymbol>[];
    for (int i = 0; elfBinary.static_symbols[i].address != 0; i++) {
      staticSymbols.add(ElfSymbol(elfSymbol: elfBinary.static_symbols[i][0]));
    }
  }
}

class ElfHeader {
  final Elf_Header_t elfHeader;
  late Uint8List identity = Uint8List(LIEF_ELF_IDENTITY.LIEF_ELF_EI_NIDENT);
  late int fileType;
  late int machineType;
  late int objectFileVersion;
  late int entrypoint;
  late int programHeadersOffset;
  late int sectionHeadersOffset;
  late int processorFlags;
  late int headerSize;
  late int programHeaderSize;
  late int numberofSegments;
  late int sectionHeaderSize;
  late int numberofSections;
  late int nameStringTableIdx;

  ElfHeader({required this.elfHeader}) {
    for (int i = 0; i < identity.length; i++) {
      identity[i] = elfHeader.identity[i];
    }
    fileType = elfHeader.file_type;
    machineType = elfHeader.machine_type;
    objectFileVersion = elfHeader.object_file_version;
    entrypoint = elfHeader.entrypoint;
    programHeadersOffset = elfHeader.program_headers_offset;
    sectionHeadersOffset = elfHeader.section_headers_offset;
    processorFlags = elfHeader.processor_flags;
    headerSize = elfHeader.header_size;
    programHeaderSize = elfHeader.program_header_size;
    numberofSegments = elfHeader.numberof_segments;
    sectionHeaderSize = elfHeader.section_header_size;
    numberofSections = elfHeader.numberof_sections;
    nameStringTableIdx = elfHeader.name_string_table_idx;
  }
}

class ElfSection {
  final Elf_Section_t elfSection;
  late String name;
  late int flags;
  late int type;
  late int virtualAddress;
  late int offset;
  late int originalSize;
  late int link;
  late int info;
  late int alignment;
  late int entrySize;
  late int size;
  // TODO: content
  late double entropy;

  ElfSection({required this.elfSection}) {
    name = elfSection.name.cast<Utf8>().toDartString();
    flags = elfSection.flags;
    type = elfSection.type;
    virtualAddress = elfSection.virtual_address;
    offset = elfSection.offset;
    originalSize = elfSection.original_size;
    link = elfSection.link;
    info = elfSection.info;
    alignment = elfSection.alignment;
    entrySize = elfSection.entry_size;
    size = elfSection.size;
  }
}

class ElfSegment {
  final Elf_Segment_t elfSegment;
  late int type;
  late int flags;
  late int virtualAddress;
  late int virtualSize;
  late int offset;
  late int alignment;
  late int size;
  // TODO: content

  ElfSegment({required this.elfSegment}) {
    type = elfSegment.type;
    flags = elfSegment.flags;
    virtualAddress = elfSegment.virtual_address;
    virtualSize = elfSegment.virtual_size;
    offset = elfSegment.offset;
    alignment = elfSegment.alignment;
    size = elfSegment.size;
  }
}

class ElfDynamicEntry {
  final Elf_DynamicEntry_t elfDynamicEntry;
  late int tag;
  late int value;

  ElfDynamicEntry({required this.elfDynamicEntry}) {
    tag = elfDynamicEntry.tag;
    value = elfDynamicEntry.value;
  }
}

class ElfSymbol {
  final Elf_Symbol_t elfSymbol;
  late String name;
  late int type;
  late int binding;
  late int information;
  late int other;
  late int shndx;
  late int value;
  late int size;
  late int isExported;
  late int isImported;

  ElfSymbol({required this.elfSymbol}) {
    name = elfSymbol.name.cast<Utf8>().toDartString();
    type = elfSymbol.type;
    binding = elfSymbol.binding;
    information = elfSymbol.information;
    other = elfSymbol.other;
    shndx = elfSymbol.shndx;
    value = elfSymbol.value;
    size = elfSymbol.size;
    isExported = elfSymbol.is_exported;
    isImported = elfSymbol.is_imported;
  }
}
