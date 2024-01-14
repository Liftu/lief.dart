/// Dart bindings for LIEF.
///
///
library;

import 'dart:io';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart';

import 'src/bindings/LIEF_bindings.dart';
import 'src/pe.dart';

export 'src/pe.dart';

class Lief {
  static final Lief _instance = Lief._internal();

  factory Lief() {
    return _instance;
  }

  static const String ARCH_X64 = "x64";
  static const String ARCH_X86 = "x86";
  static const String ARCH_AARCH64 = "aarch64";
  static const String ARCH_ARM32 = "arm32";

  static final String libsPath = join(Directory.current.path, "LIEF", "lib");
  static final String linuxAarch64LibPath =
      join(libsPath, "libLIEF_linux_${ARCH_AARCH64}.so");
  static final String linuxX64LibPath =
      join(libsPath, "libLIEF_linux_${ARCH_X64}.so");
  static final String androidAarch64LibPath =
      join(libsPath, "libLIEF_android_${ARCH_AARCH64}.so");
  static final String androidArm32LibPath =
      join(libsPath, "libLIEF_android_${ARCH_ARM32}.so");
  static final String macosAarch64LibPath =
      join(libsPath, "libLIEF_macos_${ARCH_AARCH64}.dylib");
  static final String macosX64LibPath =
      join(libsPath, "libLIEF_macos_${ARCH_X64}.dylib");
  static final String iosAarch64LibPath =
      join(libsPath, "libLIEF_ios_${ARCH_AARCH64}.dylib");
  static final String winX64LibPath =
      join(libsPath, "LIEF_win_${ARCH_X64}.dll");
  static final String winX86LibPath =
      join(libsPath, "LIEF_win_${ARCH_X86}.dll");

  late DynamicLibrary dylib;
  late LIEF lief;

  Lief._internal() {
    final String architecture = getArchitecture();
    String libraryPath = "";

    if (Platform.isLinux) {
      switch (architecture) {
        case ARCH_X64:
          libraryPath = linuxX64LibPath;
          break;
        case ARCH_AARCH64:
          libraryPath = linuxAarch64LibPath;
          break;
      }
    } else if (Platform.isAndroid) {
      switch (architecture) {
        case ARCH_AARCH64:
          libraryPath = androidAarch64LibPath;
          break;
        case ARCH_ARM32:
          libraryPath = androidArm32LibPath;
          break;
      }
    } else if (Platform.isMacOS) {
      switch (architecture) {
        case ARCH_X64:
          libraryPath = macosX64LibPath;
          break;
        case ARCH_AARCH64:
          libraryPath = macosAarch64LibPath;
          break;
      }
    } else if (Platform.isIOS) {
      switch (architecture) {
        case ARCH_X64:
          libraryPath = iosAarch64LibPath;
          break;
      }
    } else if (Platform.isWindows) {
      switch (architecture) {
        case ARCH_X64:
          libraryPath = winX64LibPath;
          break;
        case ARCH_X86:
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
        arch = ARCH_X64;
        break;
      case "x86" || "x32" || "i386" || "i686" || "386" || "amd32":
        arch = ARCH_X86;
        break;
      case "aarch64" || "arm64" || "armv8b" || "armv8l":
        arch = ARCH_AARCH64;
        break;
      case "arm" || "arm32" || "armv7l" || "armv6l":
        arch = ARCH_ARM32;
        break;
      default:
        throw Exception("Unknown architecture (${arch})");
    }
    return arch;
  }

  PeBinary parsePeFile(String filename) {
    Pointer<Pe_Binary_t> pPeBinary =
        lief.pe_parse(filename.toNativeUtf8().cast<Char>());
    return PeBinary(peBinary: pPeBinary[0]);
  }
}
