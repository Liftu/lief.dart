import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart';

import 'bindings/LIEF_bindings.dart';

class MachoBinary {
  final Macho_Binary_t machoBinary;
  late String name;
  late int imagebase;
  late MachoHeader header;
  late List<MachoCommand> commands;
  late List<MachoSymbol> symbols;
  late List<MachoSection> sections;
  late List<MachoSegment> segments;

  MachoBinary({required this.machoBinary}) {
    // name
    name = basename(machoBinary.name.cast<Utf8>().toDartString());

    //imagebase
    imagebase = machoBinary.imagebase;

    // header
    header = MachoHeader(machoHeader: machoBinary.header);

    // commands
    commands = <MachoCommand>[];
    for (int i = 0; i < header.nbCmds; i++) {
      commands.add(MachoCommand(machoCommand: machoBinary.commands[i][0]));
    }

    // symbols
    symbols = <MachoSymbol>[];
    for (int i = 0; machoBinary.symbols[i].address != 0; i++) {
      symbols.add(MachoSymbol(machoSymbol: machoBinary.symbols[i][0]));
    }

    // sections
    sections = <MachoSection>[];
    for (int i = 0; machoBinary.sections[i].address != 0; i++) {
      sections.add(MachoSection(machoSection: machoBinary.sections[i][0]));
    }

    // segments
    segments = <MachoSegment>[];
    for (int i = 0, sectionIdx = 0; machoBinary.segments[i].address != 0; i++) {
      MachoSegment segment =
          MachoSegment(machoSegment: machoBinary.segments[i][0]);
      // Add sections to segment object
      for (int j = 0; j < segment.numberofSections; j++, sectionIdx++) {
        segment.sections.add(sections[sectionIdx]);
      }
      segments.add(segment);
    }
  }
}

class MachoHeader {
  final Macho_Header_t machoHeader;
  late int magic;
  late int cpuType;
  late int cpuSubtype;
  late int fileType;
  late int nbCmds;
  late int sizeofCmds;
  late int flags;
  late int reserved;

  MachoHeader({required this.machoHeader}) {
    magic = machoHeader.magic;
    cpuType = machoHeader.cpu_type;
    cpuSubtype = machoHeader.cpu_subtype;
    fileType = machoHeader.file_type;
    nbCmds = machoHeader.nb_cmds;
    sizeofCmds = machoHeader.sizeof_cmds;
    flags = machoHeader.flags;
    reserved = machoHeader.reserved;
  }
}

class MachoCommand {
  final Macho_Command_t machoCommand;
  late int command;
  late int size;
  late Uint8List data = Uint8List(0);
  late int offset;

  MachoCommand({required this.machoCommand}) {
    command = machoCommand.command;
    size = machoCommand.size;
    if (machoCommand.data.address != 0) {
      data = machoCommand.data.asTypedList(size);
    }
    offset = machoCommand.offset;
  }
}

class MachoSymbol {
  final Macho_Symbol_t machoSymbol;
  late String name;
  late int type;
  late int numberofSections;
  late int description;
  late int value;

  MachoSymbol({required this.machoSymbol}) {
    name = machoSymbol.name.cast<Utf8>().toDartString();
    type = machoSymbol.type;
    numberofSections = machoSymbol.numberof_sections;
    description = machoSymbol.description;
    value = machoSymbol.value;
  }
}

class MachoSection {
  final Macho_Section_t machoSection;
  late String name;
  late int alignment;
  late int relocationOffset;
  late int numberofRelocations;
  late int flags;
  late int type;
  late int reserved1;
  late int reserved2;
  late int reserved3;
  late int virtualAddress;
  late int offset;
  late int size;
  late Uint8List content = Uint8List(0);
  late double entropy;

  MachoSection({required this.machoSection}) {
    name = machoSection.name.cast<Utf8>().toDartString();
    alignment = machoSection.alignment;
    relocationOffset = machoSection.relocation_offset;
    numberofRelocations = machoSection.numberof_relocations;
    flags = machoSection.flags;
    type = machoSection.type;
    reserved1 = machoSection.reserved1;
    reserved2 = machoSection.reserved2;
    reserved3 = machoSection.reserved3;
    virtualAddress = machoSection.virtual_address;
    offset = machoSection.offset;
    size = machoSection.size;
    if (machoSection.content.address != 0) {
      content = machoSection.content.asTypedList(size);
    }
    entropy = machoSection.entropy;
  }
}

class MachoSegment {
  final Macho_Segment_t machoSegment;
  late String name;
  late int virtualAddress;
  late int virtualSize;
  late int fileSize;
  late int fileOffset;
  late int maxProtection;
  late int initProtection;
  late int numberofSections;
  late int flags;
  late Uint8List content = Uint8List(0);
  late int size;
  late List<MachoSection> sections;

  MachoSegment({required this.machoSegment}) {
    name = machoSegment.name.cast<Utf8>().toDartString();
    virtualAddress = machoSegment.virtual_address;
    virtualSize = machoSegment.virtual_size;
    fileSize = machoSegment.file_size;
    fileOffset = machoSegment.file_offset;
    maxProtection = machoSegment.max_protection;
    initProtection = machoSegment.init_protection;
    numberofSections = machoSegment.numberof_sections;
    flags = machoSegment.flags;
    size = machoSegment.size;
    if (machoSegment.content.address != 0) {
      content = machoSegment.content.asTypedList(size);
    }
    sections = <MachoSection>[];
    if (machoSegment.sections.address != 0) {
      for (int i = 0; i < numberofSections; i++) {
        sections.add(MachoSection(machoSection: machoSegment.sections[i][0]));
      }
    }
  }
}
