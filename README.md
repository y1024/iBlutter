# iBlutter - iOS Flutter App Reverse Engineering Tool

```text
  _  ____  _       _   _              
 (_)| __ )| |_   _| |_| |_ ___ _ __  
 | ||  _ \| | | | | __| __/ _ \ '__| 
 | || |_) | | |_| | |_| ||  __/ |    
 |_||____/ |_|\__,_|\__|\__\___|_|   
                                      
  iBlutter - iOS Flutter RE Tool      
```

**iBlutter** is a specialized, all-in-one reverse engineering toolkit designed specifically for **iOS Flutter applications**.

It acts as a comprehensive wrapper and enhancement for [Blutter](https://github.com/worawit/blutter) (the leading Flutter reverse engineering engine). Because iOS Flutter apps compile Dart into Mach-O binaries rather than standard ELF shared libraries (like Android's `libapp.so`), standard Blutter cannot process them natively. 

iBlutter bridges this gap by providing an automated pipeline that:
1. Extracts iOS `.ipa` files automatically.
2. Locates the correct Dart snapshot binary (usually inside `App.framework/App`).
3. Performs a real-time **Mach-O to ELF** conversion of the binary in memory.
4. Feeds the resulting ELF into a specially patched Blutter engine.
5. Generates clean, ready-to-use Frida scripts, IDA Pro scripts, and ARM64 assembly dumps.

---

## Features

- **Automated iOS Extraction**: Pass it a raw `.ipa` file or a bare Mach-O binary. iBlutter handles the extraction and location of the Dart VM snapshot.
- **Mach-O to ELF Conversion**: Custom `macho_to_elf` engine reconstructs Mach-O segments, symbols, and relocations into an ELF format that Blutter can parse.
- **Dart Auto-Detection**: Automatically attempts to identify the compiled Dart SDK version from the binary strings.
- **Noise Reduction**: Cleans up Blutter's terminal output to show only what matters, suppressing verbose parsing errors.
- **Jailbreak Ready Outputs**: Automatically generates Frida scripts tailored for dynamic instrumentation on jailbroken iOS devices.

---

## Requirements & Setup

iBlutter is currently built to run on **Windows 10/11 (x64)** due to the compiled Blutter executable engines.

### System Prerequisites

1. **Python 3.10+** installed on your system.
2. **Visual C++ Redistributable 2022** (`VC_redist.x64.exe`) — Required for the pre-compiled C++ Blutter binaries in the `bin/` folder to run.

### Python Dependencies

Install the required Python modules via pip:

```bash
pip install -r requirements.txt
```

> **Note on LIEF:** iBlutter relies heavily on the `lief` library to parse and reconstruct executable formats. 

### Bundle Contents
The `bin/` directory contains pre-compiled `.exe` files and required DLLs (`capstone.dll`, `icudt73.dll`, `icuuc73.dll`). Do not remove or move these files, as `iblutter.py` relies on them to execute the backend C++ analysis.

---

## Usage

The main entry point is `iblutter.py`.

### Scenario 1: Analyzing an iOS `.ipa` File (Recommended)
You can point iBlutter directly at an IPA file. It will extract it to a temporary directory, locate the correct Mach-O binary containing the Dart symbols, and analyze it.

```bash
python iblutter.py -i C:\Path\To\YourApp.ipa -o C:\Path\To\OutputDirectory
```

### Scenario 2: Analyzing a raw iOS Mach-O Binary
If you have already extracted the app or pulled the binary from a jailbroken device, you can pass the raw Mach-O file directly (usually found at `Payload/Runner.app/Frameworks/App.framework/App`).

```bash
python iblutter.py -i C:\Path\To\Extracted\App -o C:\Path\To\OutputDirectory
```

### Scenario 3: Manually Specifying the Dart Version
iBlutter tries to auto-detect the Dart version. If it fails, or if you want to force a specific version, use the `--dart-version` flag.

```bash
python iblutter.py -i YourApp.ipa -o ./output --dart-version 3.10.7
```

### Scenario 4: Keeping the Intermediate ELF File
If you want to manually inspect the converted Mach-O -> ELF binary in tools like IDA Pro or Ghidra, use the `--keep-elf` flag.

```bash
python iblutter.py -i YourApp.ipa -o ./output --keep-elf
```

---

## Understanding the Output

Once iBlutter finishes successfully, your output directory will be populated with several highly valuable artifacts:

| File / Folder | What is it? | How to use it |
|---|---|---|
| `asm/` | A directory tree mirroring the Dart package structure. Contains `.asm` files mapping Dart methods to ARM64 assembly with inline object pool references. | Open in VSCode/Sublime to statically analyze app logic and find interesting offsets. |
| `blutter_frida.js` | A generated Frida script containing templates and offsets to hook almost any Dart function in the app. | `frida -U -f com.your.app -l blutter_frida.js` |
| `ida_script/addNames.py` | An IDA Pro Python script that renames all generic `sub_XXXXXX` functions to their actual Dart class and method names. | Open the binary in IDA Pro -> File -> Script File -> select this script. |
| `ida_script/ida_dart_struct.h` | C-style Header definitions of internal Dart VM structures (Strings, Arrays, Contexts). | Load into IDA Pro to apply correct types to memory structures. |
| `pp.txt` | The complete Dart Object Pool. | Use this to search for hardcoded API keys, URLs, and encryption constants. |
| `objs.txt` | A dump of known Dart heap objects. | Useful for understanding the static state of the application. |

---

## Supported Versions

Currently, the pre-compiled bin folder ships with support for:

| Dart Version | Architecture | Pointer Compression |
|---|---|---|
| **3.10.7** | iOS ARM64 | `no-compressed-ptrs` |

*Note: The vast majority of production iOS Flutter applications are compiled with `no-compressed-ptrs` enabled.*

---

## Troubleshooting

**"No Dart symbols found in binary"**
Ensure you are pointing iBlutter at the correct file. The main executable (`Payload/Runner.app/Runner`) often does *not* contain the Dart snapshot on iOS. The Dart snapshot is usually compiled into a separate framework located at `Payload/Runner.app/Frameworks/App.framework/App`. If providing an `.ipa`, iBlutter handles this search automatically.

**"No Blutter binary for Dart version X.X.X"**
You must have a matching `.exe` in the `bin/` folder for the specific Dart version the app was compiled with.

**The script crashes during `macho_to_elf` conversion**
Ensure you are passing a valid ARM64 Mach-O file. Fat binaries (Universal Binaries) are supported, and iBlutter will attempt to extract the ARM64 slice automatically.

---

## License & Credits

This tool is designed for **security researchers, penetration testers, and reverse engineers** to analyze applications they have legal authorization to test. 

- **Blutter Backend Engine**: Originally created by [@worawit](https://github.com/worawit/blutter). All credit for the incredible Dart VM snapshot parsing engine goes to them.
- **iBlutter Enhancements**: iOS `.ipa` extraction, Mach-O to ELF bridging, and automated pipeline handling by the iBlutter team.
- Built using [LIEF](https://lief-project.github.io/) and [Capstone](https://www.capstone-engine.org/).

