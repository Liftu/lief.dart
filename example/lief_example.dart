import 'dart:typed_data';

import 'package:lief/lief.dart';

void main() {
  elfExample();
  machoExample();
  peExample();
}

void elfExample() {
  print("\n\n=== Parsing ELF binary ===");
  ElfBinary binary = Lief().parseElfFile("LIEF/lib/libLIEF_linux_x64.so");

  print("ELF file: ${binary.name}");
  print(
      "Magic: 0x${ByteData.view(binary.header.identity.buffer).getInt32(0, Endian.little).toRadixString(16).toUpperCase()}");

  if (binary.interpreter.isNotEmpty) {
    print("Interpreter: ${binary.interpreter}");
  }

  if (binary.dynamicSymbols.isNotEmpty) {
    print("\nSections:");
    for (int i = 0; i < binary.sections.length && i < 10; i++) {
      print("\t\"${binary.sections[i].name}\"");
    }
  }

  if (binary.dynamicSymbols.isNotEmpty) {
    print("\nDynamic symbols:");
    for (int i = 0; i < binary.dynamicSymbols.length && i < 10; i++) {
      print("\t\"${binary.dynamicSymbols[i].name}\"");
    }
  }

  if (binary.staticSymbols.isNotEmpty) {
    print("\nStatic symbols:");
    for (int i = 0; i < binary.staticSymbols.length && i < 10; i++) {
      print("\"\t${binary.staticSymbols[i].name}\"");
    }
  }
}

void machoExample() {
  print("\n\n=== Parsing Mach-O binary ===");
  MachoBinary binary = Lief().parseMachoFile("example/MachO-OSX-x64-ls");

  print("Mach-O file: ${binary.name}");
  print("Magic: 0x${binary.header.magic.toRadixString(16).toUpperCase()}");

  if (binary.segments.isNotEmpty) {
    print("\nSegments:");
    for (int i = 0; i < binary.segments.length && i < 4; i++) {
      print("\t\"${binary.segments[i].name}\":");

      if (binary.segments[i].sections.isNotEmpty) {
        for (int j = 0; j < binary.segments[i].sections.length && j < 5; j++) {
          print("\t\t\"${binary.segments[i].sections[j].name}\"");
        }
      }
    }
  }

  if (binary.symbols.isNotEmpty) {
    print("\nSymbols:");
    for (int i = 0; i < binary.symbols.length && i < 10; i++) {
      print("\t\"${binary.symbols[i].name}\"");
    }
  }
}

void peExample() {
  print("\n\n=== Parsing PE binary ===");
  PeBinary binary = Lief().parsePeFile("LIEF/lib/LIEF_win_x86.dll");

  print("PE file: ${binary.name}");
  print("Magic: 0x${binary.dosHeader.magic.toRadixString(16).toUpperCase()}");

  if (binary.sections.isNotEmpty) {
    print("\nSections:");
    for (final PeSection section in binary.sections) {
      print("\t${section.name}");
    }
  }

  if (binary.imports.isNotEmpty) {
    print("\nImported libs:");
    for (int i = 0; i < binary.imports.length && i < 4; i++) {
      print("\t\"${binary.imports[i].name}\":");

      if (binary.imports[i].entries.isNotEmpty) {
        for (int j = 0; j < binary.imports[i].entries.length && j < 4; j++) {
          print("\t\t\"${binary.imports[i].entries[j].name}\"");
        }
      }
    }
  }
}
