import 'dart:typed_data';

import 'package:lief/lief.dart';

void main() {
  elf_example();
  pe_example();
}

void elf_example() {
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

void pe_example() {
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
