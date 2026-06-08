#!/usr/bin/env python3
"""
iBlutter - iOS Flutter App Reverse Engineering Tool
====================================================
Combines Mach-O -> ELF conversion with Blutter analysis for iOS Flutter apps.

Supports:
  - iOS IPA files (extracts the app binary automatically)
  - Raw Mach-O / Fat Binary app files
  - Arm64 only (no-compressed-ptrs, Dart 3.x)

Usage:
  python iblutter.py -i <path/to/App.ipa or Runner.app/Runner> -o <output_dir> [--dart-version 3.10.7]
"""

import argparse
import os
import sys
import shutil
import subprocess
import zipfile
import tempfile
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "scripts")

# Maps Dart version -> compiled blutter exe name in bin/
BLUTTER_BINS = {
    "3.10.7": "blutter_dartvm3.10.7_ios_arm64_no-compressed-ptrs.exe",
}

DEFAULT_DART_VERSION = "3.10.7"


def banner():
    print(r"""
  _  ____  _       _   _              
 (_)| __ )| |_   _| |_| |_ ___ _ __  
 | ||  _ \| | | | | __| __/ _ \ '__| 
 | || |_) | | |_| | |_| ||  __/ |    
 |_||____/ |_|\__,_|\__|\__\___|_|   
                                      
  iBlutter - iOS Flutter RE Tool       
  ------------------------------------
""")


DART_SYMBOLS_REQUIRED = [
    '_kDartVmSnapshotData', '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData', '_kDartIsolateSnapshotInstructions',
    'kDartVmSnapshotData', 'kDartVmSnapshotInstructions',
    'kDartIsolateSnapshotData', 'kDartIsolateSnapshotInstructions',
]


def binary_has_dart_symbols(path):
    """Quick check: does this Mach-O binary have any Dart snapshot symbols?"""
    try:
        import lief as _lief
        m = _lief.parse(path)
        if isinstance(m, _lief.MachO.FatBinary):
            m = m.take(_lief.MachO.CPU_TYPES.ARM64)
        if m is None:
            return False
        found = {sym.name for sym in m.symbols}
        return any(s in found for s in DART_SYMBOLS_REQUIRED)
    except Exception:
        return False


def find_app_binary_in_ipa(ipa_path, tmpdir):
    """Extract IPA and find the Mach-O binary that contains Dart snapshot symbols.

    Search order (most specific first):
      1. Frameworks/App.framework/App  -- Flutter Dart snapshot lives here
      2. <AppName>.app/<AppName>       -- Main app binary (fallback)
    """
    print(f"[*] Extracting IPA: {ipa_path}")
    with zipfile.ZipFile(ipa_path, 'r') as z:
        z.extractall(tmpdir)

    payload_dir = os.path.join(tmpdir, "Payload")
    if not os.path.exists(payload_dir):
        raise FileNotFoundError("No 'Payload' folder found inside IPA. Is this a valid IPA?")

    candidates = []  # (path, label) in preference order

    for app_bundle in os.listdir(payload_dir):
        if not app_bundle.endswith(".app"):
            continue
        app_path = os.path.join(payload_dir, app_bundle)

        # 1. Flutter App.framework (most likely to hold Dart symbols)
        fw = os.path.join(app_path, "Frameworks", "App.framework", "App")
        if os.path.isfile(fw):
            candidates.append((fw, "Frameworks/App.framework/App"))

        # 2. Main Runner binary
        binary_name = app_bundle[:-4]
        main_bin = os.path.join(app_path, binary_name)
        if os.path.isfile(main_bin):
            candidates.append((main_bin, f"{binary_name} (main binary)"))

    if not candidates:
        raise FileNotFoundError("Could not find any Mach-O binary inside the IPA.")

    # Pick the first candidate that actually has Dart symbols
    for path, label in candidates:
        print(f"[*] Checking {label} for Dart symbols...")
        if binary_has_dart_symbols(path):
            print(f"[+] Dart symbols found in: {label}")
            return path
        else:
            print(f"[!] No Dart symbols in {label}, trying next...")

    # Last resort — return first candidate and let macho_to_elf handle the error
    path, label = candidates[0]
    print(f"[!] No binary with Dart symbols found. Trying {label} anyway...")
    return path


def detect_dart_version_from_binary(binary_path):
    """Try to extract the Dart version string from the binary."""
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        # Look for Dart version string pattern like '3.10.7 (stable)'
        m = re.search(rb'(\d+\.\d+\.\d+)\s+\((?:stable|beta|dev)\)', data)
        if m:
            version = m.group(1).decode()
            print(f"[+] Auto-detected Dart version: {version}")
            return version
    except Exception:
        pass
    return None


def convert_macho_to_elf(binary_path, output_elf_path):
    """Invoke macho_to_elf.py converter."""
    converter = os.path.join(SCRIPT_DIR, "macho_to_elf.py")
    if not os.path.exists(converter):
        raise FileNotFoundError(f"macho_to_elf.py not found at {converter}")

    import lief as _lief
    if not _lief.is_macho(binary_path):
        fmt = "ELF" if _lief.is_elf(binary_path) else "unknown"
        print(f"[-] Input binary is {fmt} format, not Mach-O.")
        print(f"    iBlutter only processes iOS Mach-O app binaries or .ipa files.")
        print(f"    For Android ELF libapp.so, use the original Blutter tool instead.")
        sys.exit(1)

    # Import and call directly
    sys.path.insert(0, SCRIPT_DIR)
    from macho_to_elf import convert_macho_to_elf as _convert
    print(f"[*] Converting Mach-O to ELF...")
    _convert(binary_path, None, output_elf_path)
    print(f"[+] ELF written to: {output_elf_path}")


def run_blutter(elf_path, output_dir, dart_version, verbose=False):
    """Run the Blutter binary on the converted ELF with clean filtered output."""
    exe_name = BLUTTER_BINS.get(dart_version)
    if not exe_name:
        available = ", ".join(BLUTTER_BINS.keys())
        raise ValueError(
            f"No Blutter binary for Dart version '{dart_version}'.\n"
            f"Available versions: {available}\n"
            f"Use --dart-version to specify one."
        )

    exe_path = os.path.join(BIN_DIR, exe_name)
    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"Blutter binary not found: {exe_path}")

    print(f"[*] Running Blutter ({dart_version})...")
    print(f"    Binary : {exe_path}")
    print(f"    Input  : {elf_path}")
    print(f"    Output : {output_dir}")
    print()

    # Lines that are always shown regardless of verbose mode
    IMPORTANT_PREFIXES = (
        "Dumping Object Pool",
        "Dumping Objects",
        "Generating application",
        "Dumping 4Ida",
        "Generating Frida",
        "AnalyzeAll: iteration",
        "AnalyzeAll: lib",     # only show library switches, not per-function
        "main:",
    )
    # Lines/patterns to always suppress (noise)
    SUPPRESS_PREFIXES = (
        "  Analyzing function:",
        "Analysis error at line",
        "    0x",              # assembly context lines
        "  * 0x",             # current-instruction marker
        "  DumpStructHeaderFile",
        "  Dump4Ida",
        "  Written ELF",
        "  .text:",
        "  .rodata:",
        "  _kDart",
    )

    fn_count = 0
    err_count = 0
    cur_lib = ""
    lib_fn_count = 0

    proc = subprocess.Popen(
        [exe_path, "-i", elf_path, "-o", output_dir],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "PATH": BIN_DIR + os.pathsep + os.environ.get("PATH", "")},
        text=True, encoding="utf-8", errors="replace",
        bufsize=1,
    )

    for line in proc.stdout:
        line_stripped = line.rstrip()

        if verbose:
            print(line_stripped)
            continue

        # Count analysis errors silently
        if line_stripped.startswith("Analysis error at line"):
            err_count += 1
            continue

        # Count analyzed functions, print per-library summary
        if line_stripped.startswith("  Analyzing function:"):
            fn_count += 1
            lib_fn_count += 1
            continue

        # Suppress other noisy lines
        if any(line_stripped.startswith(p) for p in SUPPRESS_PREFIXES):
            continue

        # Detect library transitions and print summary
        if line_stripped.startswith("AnalyzeAll: lib"):
            lib_name = line_stripped.replace("AnalyzeAll: lib", "").strip()
            if cur_lib and lib_fn_count > 0:
                print(f"    [{lib_fn_count:>5} functions]  {cur_lib}")
            cur_lib = lib_name if lib_name else "(core)"
            lib_fn_count = 0
            continue

        # Print all other important lines as-is
        print(line_stripped)

    # Flush last library
    if cur_lib and lib_fn_count > 0:
        print(f"    [{lib_fn_count:>5} functions]  {cur_lib}")

    proc.wait()

    print()
    print(f"[*] Analysis summary: {fn_count} functions processed, {err_count} non-critical analysis warnings")

    if proc.returncode != 0:
        print(f"\n[-] Blutter exited with code {proc.returncode}")
        sys.exit(proc.returncode)
    else:
        print(f"[+] Blutter completed successfully!")


def print_results(output_dir):
    print("\n" + "="*55)
    print("  iBlutter - Analysis Complete!")
    print("="*55)
    artifacts = {
        "asm/":              "Dart class/method structure (human-readable)",
        "blutter_frida.js":  "Frida instrumentation script",
        "ida_script/":       "IDA Pro auto-labeling scripts",
        "pp.txt":            "Dart Object Pool map",
        "objs.txt":          "Known Dart objects dump",
    }
    for name, desc in artifacts.items():
        full = os.path.join(output_dir, name)
        exists = os.path.exists(full)
        mark = "[OK]" if exists else "[--]"
        print(f"  {mark} {name:<25} {desc}")
    print("="*55)
    print(f"\n  Output directory: {output_dir}\n")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="iBlutter - iOS Flutter App Reverse Engineering Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python iblutter.py -i MyApp.ipa -o ./output
  python iblutter.py -i Runner -o ./output --dart-version 3.10.7
  python iblutter.py -i MyApp.ipa -o ./output --keep-elf
  python iblutter.py -i MyApp.ipa -o ./output --verbose
        """
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Path to IPA file or raw Mach-O app binary")
    parser.add_argument("-o", "--output", required=True,
                        help="Output directory for all generated artifacts")
    parser.add_argument("--dart-version", default=None,
                        help=f"Dart version to use. Default: auto-detect, fallback {DEFAULT_DART_VERSION}")
    parser.add_argument("--keep-elf", action="store_true",
                        help="Keep the intermediate libapp.so ELF file after analysis")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all Blutter output including per-function analysis (very noisy)")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    tmpdir = None

    try:
        # Step 1: Find the binary
        if input_path.endswith(".ipa"):
            tmpdir = tempfile.mkdtemp(prefix="iblutter_")
            binary_path = find_app_binary_in_ipa(input_path, tmpdir)
        else:
            binary_path = input_path
            if not os.path.isfile(binary_path):
                print(f"[-] Input file not found: {binary_path}")
                sys.exit(1)

        # Step 2: Auto-detect Dart version
        dart_version = args.dart_version
        if dart_version is None:
            dart_version = detect_dart_version_from_binary(binary_path)
        if dart_version is None:
            dart_version = DEFAULT_DART_VERSION
            print(f"[!] Could not auto-detect Dart version. Using default: {dart_version}")

        # Step 3: Convert Mach-O -> ELF
        elf_path = os.path.join(output_dir, "libapp.so")
        convert_macho_to_elf(binary_path, elf_path)

        # Step 4: Run Blutter
        run_blutter(elf_path, output_dir, dart_version, verbose=args.verbose)

        # Step 5: Cleanup
        if not args.keep_elf and os.path.exists(elf_path):
            os.remove(elf_path)
            print(f"[*] Removed intermediate ELF (use --keep-elf to keep it)")

        print_results(output_dir)

    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
