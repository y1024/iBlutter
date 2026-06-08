# iBlutter — Technical Internals

## Why This Tool Exists

Blutter (the original) was designed for Android Flutter apps which ship as standard ELF shared libraries (`libapp.so`).
iOS Flutter apps instead ship as Mach-O binaries embedded inside an `.ipa` archive. The Dart VM snapshot data and instruction segments have to be **manually extracted and repackaged** into an ELF format that Blutter's analysis engine can consume.

Additionally, iOS Flutter apps use a different Dart VM compilation flag: `--no-compressed-pointers`, which requires a specially compiled Blutter engine. The standard Android Blutter binaries will not work.

---

## Pipeline Architecture

```
IPA/Mach-O Binary
       │
       ▼
[Step 1] IPA Extraction (if .ipa input)
  - zipfile extraction
  - Payload/<App>.app/<BinaryName> detection
       │
       ▼
[Step 2] Dart Symbol Discovery (macho_to_elf.py)
  - lief.parse() → MachO binary
  - Scan symbol table for:
      _kDartVmSnapshotData
      _kDartVmSnapshotInstructions
      _kDartIsolateSnapshotData
      _kDartIsolateSnapshotInstructions
  - Calculate sizes using section boundaries + Image headers
       │
       ▼
[Step 3] ELF Synthesis (_build_elf64)
  - Build a minimal ELF64 AArch64 shared object from scratch
  - Layout:
      ELF header (64 bytes)
      Program headers (6 × 56 bytes)
      .note.gnu.build-id
      .dynstr  (Dart symbol names)
      .dynsym  (6 global symbols)
      .hash    (SYSV hash table)
      .rodata  (VM + Isolate snapshot DATA)
      .text    (VM + Isolate snapshot INSTRUCTIONS)
      .dynamic (DT_HASH, DT_STRTAB, DT_SYMTAB, …)
      .bss
      .shstrtab
      Section headers
       │
       ▼
[Step 4] Blutter Analysis Engine
  - blutter_dartvm3.10.7_ios_arm64_no-compressed-ptrs.exe
  - Initializes Dart VM in snapshot mode
  - Parses class table, object pool, function list
  - Disassembles ARM64 instructions with inline annotations
  - Generates output artifacts
```

---

## Key iOS vs Android Differences

| Aspect | Android | iOS |
|---|---|---|
| Binary format | ELF `.so` | Mach-O (Fat or thin ARM64) |
| Compressed pointers | Yes (`--compressed-ptrs`) | No (`--no-compressed-ptrs`) |
| Symbol prefix | `_kDart...` (no leading `_`) | `_kDart...` (with leading `_`) |
| Snapshot location | Separate `libapp.so` | Embedded in main app binary |
| Entry point (`e_entry`) | Non-zero | Must be set to `0` |

---

## Patches Applied to Blutter for iOS Support

### 1. DartApp.cpp — Bounds-safe Class Table Loading
- iOS obfuscated binaries may have class IDs that exceed the initial vector size.
- Fixed: dynamic `resize()` before each `classes[id]` access.

### 2. DartClass.cpp — Null SuperClass Handling
- The null sentinel class (`dart::kNullCid`) has no superclass.
- Fixed: Added explicit null check before `superCls->id` dereference.

### 3. DartFunction.cpp — Zero Entry Point Handling
- Obfuscated iOS apps sometimes strip entry points, returning `0`.
- Fixed: Treat `entry_point == 0` as a payload-based function without monomorphic prefix.

### 4. DartDumper.cpp — Null Function Pointer in Object Pool
- `app.GetFunction(imm - base)` can return `nullptr` for unlinked call targets pointing outside the known function map.
- Fixed: Null check before `dartFn->Address()` and `dartFn->FullName()` calls.

### 5. DartDumper.cpp — Empty Function Name Guard
- `fnName.back()` on an empty string is undefined behavior.
- Fixed: Early return before character suffix analysis if `fnName.empty()`.

---

## ELF Layout Details

The synthesized ELF uses **identity mapping** — virtual addresses equal file offsets for simplicity. This works because Blutter only needs to parse the ELF structure to locate snapshot segments; it does not actually `mmap()` the file as-is.

The critical constraint is that:
- `.rodata` must start at offset `0x340` (Blutter hardcodes this assumption)
- `.text` must be in a separate `PT_LOAD` segment with `PF_X` (executable) flag
- All 4 Dart symbols must appear in `.dynsym` with correct sizes
