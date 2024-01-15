/// Dart bindings for LIEF.
///
///
library;

import 'dart:io';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart';

import 'src/bindings/LIEF_bindings.dart';
import 'src/elf.dart';
import 'src/macho.dart';
import 'src/pe.dart';

export 'src/pe.dart';
export 'src/macho.dart';
export 'src/elf.dart';

class Lief {
  static final Lief _instance = Lief._internal();

  factory Lief() {
    return _instance;
  }

  static const String archX64 = "x64";
  static const String archX86 = "x86";
  static const String archAarch64 = "aarch64";
  static const String archArm32 = "arm32";

  static final String libsPath = join(Directory.current.path, "LIEF", "lib");
  static final String linuxAarch64LibPath =
      join(libsPath, "libLIEF_linux_$archAarch64.so");
  static final String linuxX64LibPath =
      join(libsPath, "libLIEF_linux_$archX64.so");
  static final String androidAarch64LibPath =
      join(libsPath, "libLIEF_android_$archAarch64.so");
  static final String androidArm32LibPath =
      join(libsPath, "libLIEF_android_$archArm32.so");
  static final String macosAarch64LibPath =
      join(libsPath, "libLIEF_macos_$archAarch64.dylib");
  static final String macosX64LibPath =
      join(libsPath, "libLIEF_macos_$archX64.dylib");
  static final String iosAarch64LibPath =
      join(libsPath, "libLIEF_ios_$archAarch64.dylib");
  static final String winX64LibPath = join(libsPath, "LIEF_win_$archX64.dll");
  static final String winX86LibPath = join(libsPath, "LIEF_win_$archX86.dll");

  late DynamicLibrary dylib;
  late LIEF lief;

  Lief._internal() {
    final String architecture = getArchitecture();
    String libraryPath = "";

    if (Platform.isLinux) {
      switch (architecture) {
        case archX64:
          libraryPath = linuxX64LibPath;
          break;
        case archAarch64:
          libraryPath = linuxAarch64LibPath;
          break;
      }
    } else if (Platform.isAndroid) {
      switch (architecture) {
        case archAarch64:
          libraryPath = androidAarch64LibPath;
          break;
        case archArm32:
          libraryPath = androidArm32LibPath;
          break;
      }
    } else if (Platform.isMacOS) {
      switch (architecture) {
        case archX64:
          libraryPath = macosX64LibPath;
          break;
        case archAarch64:
          libraryPath = macosAarch64LibPath;
          break;
      }
    } else if (Platform.isIOS) {
      switch (architecture) {
        case archX64:
          libraryPath = iosAarch64LibPath;
          break;
      }
    } else if (Platform.isWindows) {
      switch (architecture) {
        case archX64:
          libraryPath = winX64LibPath;
          break;
        case archX86:
          libraryPath = winX86LibPath;
          break;
      }
    }

    if (libraryPath.isEmpty) {
      throw Exception("Unkown running platform (${Platform.operatingSystem})");
    }
    dylib = DynamicLibrary.open(libraryPath);
    lief = LIEF(dylib);
  }

  static String getArchitecture() {
    String arch;
    if (Platform.isWindows) {
      arch = Platform.environment["PROCESSOR_ARCHITECTURE"]!;
    } else {
      final ProcessResult info = Process.runSync("uname", ["-m"]);
      arch = info.stdout.toString().replaceAll("\n", "");
    }
    arch = arch.trim().toLowerCase();
    switch (arch) {
      case "x86_64" || "x64" || "amd64":
        arch = archX64;
        break;
      case "x86" || "x32" || "i386" || "i686" || "386" || "amd32":
        arch = archX86;
        break;
      case "aarch64" || "arm64" || "armv8b" || "armv8l":
        arch = archAarch64;
        break;
      case "arm" || "arm32" || "armv7l" || "armv6l":
        arch = archArm32;
        break;
      default:
        throw Exception("Unknown architecture ($arch)");
    }
    return arch;
  }

  PeBinary parsePeFile(String filename) {
    Pointer<Pe_Binary_t> pPeBinary =
        lief.pe_parse(filename.toNativeUtf8().cast<Char>());
    if (pPeBinary.address == 0) {
      throw Exception("Unable to parse PE binary ($filename)");
    }
    return PeBinary(peBinary: pPeBinary[0]);
  }

  ElfBinary parseElfFile(String filename) {
    Pointer<Elf_Binary_t> pElfBinary =
        lief.elf_parse(filename.toNativeUtf8().cast<Char>());
    if (pElfBinary.address == 0) {
      throw Exception("Unable to parse ELF binary ($filename)");
    }
    return ElfBinary(elfBinary: pElfBinary[0]);
  }

  MachoBinary parseMachoFile(String filename) {
    Pointer<Macho_Binary_t> pElfBinary = lief.macho_parse(
        filename.toNativeUtf8().cast<Char>())[0]; // Can have multiples ?
    if (pElfBinary.address == 0) {
      throw Exception("Unable to parse Mach-O binary ($filename)");
    }
    return MachoBinary(machoBinary: pElfBinary[0]);
  }
}
