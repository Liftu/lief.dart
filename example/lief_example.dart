import 'package:lief/lief.dart';

void main() {
  PeBinary binary = Lief().parsePeFile("LIEF/lib/LIEF_win_x86.dll");
  print("PE file: ${binary.name}");
  print("Magic: ${binary.dosHeader.magic.toRadixString(16).toUpperCase()}");

  print("Sections:");
  for (final PeSection section in binary.sections) {
    print("\t${section.name}");
  }

  print("Imported libs:");
  for (final PeImport import in binary.imports) {
    print("\t${import.name}");
  }
}
