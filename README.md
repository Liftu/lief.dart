<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages).
-->

Dart bindings for the LIEF library.

This package offer the possibility to parse PE, Elf and Mach-O binaries.

## Features

Those bindings are based on the C API of LIEF, which is still very limited for the moment.

This package currently expose 3 methods:
 - `parsePeFile`
 - `parseElfFile`
 - `parseMachoFile`

Those methods take a file path to the relevant binary and will produce a `{Pe,Elf,Macho}Binary` object that contains most of the binary informations and structs.

## Getting started

This package supports Android, iOS, Linux, Windows and MacOS because dynamic library are needed for the bindings (that exclude the web support).

## Usage

Example from [here](https://github.com/Liftu/lief.dart/blob/main/example/lief_example.dart):

```dart
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
```
Result:
```
PE file: LIEF_win_x86.dll
Magic: 0x5A4D

Sections:
	.text
	.rdata
	.data
	.rsrc
	.reloc

Imported libs:
	"KERNEL32.dll":
		"Sleep"
		"GetCurrentProcessId"
		"GetDynamicTimeZoneInformation"
		"GetConsoleMode"

```

## Additional information

This project is still an experiment on Dart bindings and thus is very limited.

Many thanks to the developpers of the [LIEF Project](https://github.com/lief-project/LIEF).
