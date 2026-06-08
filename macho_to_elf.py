import lief
import os
import struct

def convert_macho_to_elf(binary_path, template_elf_path, output_elf_path):
    """Convert iOS Mach-O App binary to a synthesized libapp.so ELF.
    
    Extracts Dart snapshot segments from the Mach-O and constructs a valid
    ELF64 binary with the correct layout. Does NOT use lief for writing
    because lief has bugs with .text section content modification.
    """
    macho = lief.parse(binary_path)
    if isinstance(macho, lief.MachO.FatBinary):
        macho = macho.take(lief.MachO.CPU_TYPES.ARM64)
    
    # Map Mach-O symbol names to ELF symbol names
    dart_symbols = {
        "_kDartVmSnapshotData": "_kDartVmSnapshotData",
        "_kDartVmSnapshotInstructions": "_kDartVmSnapshotInstructions",
        "_kDartIsolateSnapshotData": "_kDartIsolateSnapshotData",
        "_kDartIsolateSnapshotInstructions": "_kDartIsolateSnapshotInstructions",
        "kDartVmSnapshotData": "_kDartVmSnapshotData",
        "kDartVmSnapshotInstructions": "_kDartVmSnapshotInstructions",
        "kDartIsolateSnapshotData": "_kDartIsolateSnapshotData",
        "kDartIsolateSnapshotInstructions": "_kDartIsolateSnapshotInstructions"
    }

    # Collect symbol info with section awareness
    symbols_info = []
    for sym in macho.symbols:
        if sym.name in dart_symbols:
            sec = macho.section_from_virtual_address(sym.value)
            sec_end = (sec.virtual_address + sec.size) if sec else 0
            symbols_info.append({
                "name": sym.name,
                "value": sym.value,
                "elf_name": dart_symbols[sym.name],
                "section_end": sec_end,
                "section_name": f"{sec.segment_name}/{sec.name}" if sec else "NONE"
            })

    symbols_info.sort(key=lambda x: x["value"])

    # Calculate sizes using section boundaries, not just next symbol
    for i, info in enumerate(symbols_info):
        # Find the next symbol in the SAME section
        next_in_section = None
        for j in range(i + 1, len(symbols_info)):
            if symbols_info[j]["section_name"] == info["section_name"]:
                next_in_section = symbols_info[j]
                break
        
        if next_in_section:
            size = next_in_section["value"] - info["value"]
        else:
            # Last symbol in its section - use distance to section end
            size = info["section_end"] - info["value"]
        
        # Also check the Image header for the true size (for Instructions sections)
        if "Instructions" in info["name"]:
            header_data = bytes(macho.get_content_from_virtual_address(info["value"], 16))
            img_size = struct.unpack_from('<Q', header_data, 0)[0]
            # Use the Image header size if it's reasonable
            if 0 < img_size <= size:
                size = img_size
        elif "Data" in info["name"]:
            # For snapshot data, read the Snapshot header to get the full blob size
            header_data = bytes(macho.get_content_from_virtual_address(info["value"], 16))
            magic = struct.unpack_from('<I', header_data, 0)[0]
            if magic == 0xdcdcf5f5:
                snap_length = struct.unpack_from('<Q', header_data, 4)[0]
                # DataImage starts at RoundUp(snap_length, 64)
                data_image_offset = (snap_length + 63) & ~63
                # Read the DataImage header
                di_header = bytes(macho.get_content_from_virtual_address(
                    info["value"] + data_image_offset, 16))
                di_size = struct.unpack_from('<Q', di_header, 0)[0]
                total_size = data_image_offset + di_size
                if 0 < total_size <= size:
                    size = total_size
        
        info["size"] = size
        info["data"] = bytes(macho.get_content_from_virtual_address(info["value"], size))
        print(f"  {info['elf_name']}: {info['section_name']} size=0x{size:x}")

    # Separate into text (instructions) and rodata (data)
    text_data = bytearray()
    rodata_data = bytearray()
    sym_offsets = {}

    for info in symbols_info:
        if "Instructions" in info["name"]:
            rem = len(text_data) % 64
            if rem != 0:
                text_data.extend(b'\x00' * (64 - rem))
            offset = len(text_data)
            text_data.extend(info["data"])
            sym_offsets[info["elf_name"]] = {"section": ".text", "offset": offset, "size": info["size"]}
        else:
            rem = len(rodata_data) % 64
            if rem != 0:
                rodata_data.extend(b'\x00' * (64 - rem))
            offset = len(rodata_data)
            rodata_data.extend(info["data"])
            sym_offsets[info["elf_name"]] = {"section": ".rodata", "offset": offset, "size": info["size"]}

    # Validate all 4 required symbols were found
    REQUIRED = {
        '_kDartVmSnapshotData', '_kDartVmSnapshotInstructions',
        '_kDartIsolateSnapshotData', '_kDartIsolateSnapshotInstructions',
    }
    found = set(sym_offsets.keys())
    missing = REQUIRED - found
    if missing:
        print(f"\n[!] ERROR: Missing required Dart symbols: {', '.join(sorted(missing))}")
        print(f"    Found:  {', '.join(sorted(found)) if found else 'none'}")
        print(f"\n    This binary does not contain the Dart VM snapshot.")
        print(f"    For Flutter iOS apps, the snapshot is usually in:")
        print(f"      Frameworks/App.framework/App")
        print(f"    and NOT in the main Runner binary.\n")
        raise ValueError(f"Missing Dart symbols: {missing}")

    # Build ELF from scratch
    _build_elf64(output_elf_path, text_data, rodata_data, sym_offsets)


def _build_elf64(output_path, text_data, rodata_data, sym_offsets):
    """Build a minimal ELF64 binary from scratch."""
    
    PAGE_SIZE = 0x1000
    
    shstrtab_strings = [
        b'\x00', b'.shstrtab\x00', b'.dynstr\x00', b'.dynsym\x00',
        b'.hash\x00', b'.rodata\x00', b'.text\x00', b'.dynamic\x00',
        b'.note.gnu.build-id\x00', b'.bss\x00',
    ]
    shstrtab = b''.join(shstrtab_strings)
    SH_NAME_SHSTRTAB = 1; SH_NAME_DYNSTR = 11; SH_NAME_DYNSYM = 19
    SH_NAME_HASH = 27; SH_NAME_RODATA = 33; SH_NAME_TEXT = 41
    SH_NAME_DYNAMIC = 47; SH_NAME_BUILDID = 56; SH_NAME_BSS = 75

    dynstr_entries = [
        b'\x00', b'_kDartVmSnapshotData\x00', b'_kDartVmSnapshotInstructions\x00',
        b'_kDartIsolateSnapshotData\x00', b'_kDartIsolateSnapshotInstructions\x00',
        b'_kDartSnapshotBuildId\x00',
    ]
    dynstr = b''.join(dynstr_entries)
    dynstr_name_offsets = {
        '_kDartVmSnapshotData': 1, '_kDartVmSnapshotInstructions': 22,
        '_kDartIsolateSnapshotData': 51, '_kDartIsolateSnapshotInstructions': 77,
        '_kDartSnapshotBuildId': 110,
    }

    ehdr_size = 64; phdr_entry_size = 56; phdr_count = 6
    shdr_entry_size = 64; shdr_count = 10

    phdr_offset = ehdr_size
    phdr_total = phdr_count * phdr_entry_size
    
    build_id_data = struct.pack('<III', 4, 16, 3) + b'GNU\x00' + b'\x00' * 16
    
    note_offset = phdr_offset + phdr_total
    note_size = len(build_id_data)
    dynstr_offset = (note_offset + note_size + 7) & ~7
    dynstr_size = len(dynstr)
    dynsym_offset = (dynstr_offset + dynstr_size + 7) & ~7
    sym_count = 6
    dynsym_size = sym_count * 24
    hash_offset = (dynsym_offset + dynsym_size + 3) & ~3
    nbucket = 5; nchain = sym_count
    hash_size = (2 + nbucket + nchain) * 4

    rodata_offset = 0x340
    rodata_size = len(rodata_data)
    rodata_vaddr = rodata_offset
    text_vaddr = (rodata_vaddr + rodata_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    text_offset = text_vaddr
    text_size = len(text_data)
    dynamic_vaddr = (text_vaddr + text_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    dynamic_offset = dynamic_vaddr
    dynamic_entries = [
        (4, hash_offset), (5, dynstr_offset), (6, dynsym_offset),
        (10, dynstr_size), (11, 24), (0, 0),
    ]
    dynamic_size = len(dynamic_entries) * 16
    bss_vaddr = dynamic_vaddr + dynamic_size
    bss_size = 0x30
    shstrtab_offset = dynamic_offset + dynamic_size + bss_size
    shstrtab_offset = (shstrtab_offset + 7) & ~7
    shstrtab_size = len(shstrtab)
    shdr_offset = (shstrtab_offset + shstrtab_size + 7) & ~7
    total_size = shdr_offset + shdr_count * shdr_entry_size

    sym_values = {}
    for elf_name, info in sym_offsets.items():
        if info["section"] == ".text":
            sym_values[elf_name] = text_vaddr + info["offset"]
        else:
            sym_values[elf_name] = rodata_vaddr + info["offset"]
    sym_values['_kDartSnapshotBuildId'] = note_offset

    buf = bytearray(total_size)

    struct.pack_into('<4sBBBBB7xHHIQQQIHHHHHH', buf, 0,
        b'\x7fELF', 2, 1, 1, 0, 0, 3, 0xB7, 1, 0, phdr_offset, shdr_offset,
        0, ehdr_size, phdr_entry_size, phdr_count, shdr_entry_size, shdr_count, shdr_count - 1)

    def write_phdr(idx, p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align):
        off = phdr_offset + idx * phdr_entry_size
        struct.pack_into('<IIQQQQqq', buf, off, p_type, p_flags, p_offset, p_vaddr, p_vaddr, p_filesz, p_memsz, p_align)

    ro_end = rodata_offset + rodata_size
    write_phdr(0, 6, 4, phdr_offset, phdr_offset, phdr_total, phdr_total, 8)
    write_phdr(1, 1, 4, 0, 0, ro_end, ro_end, PAGE_SIZE)
    write_phdr(2, 1, 5, text_offset, text_vaddr, text_size, text_size, PAGE_SIZE)
    write_phdr(3, 1, 6, dynamic_offset, dynamic_vaddr, dynamic_size + bss_size, dynamic_size + bss_size, PAGE_SIZE)
    write_phdr(4, 4, 4, note_offset, note_offset, note_size, note_size, 4)
    write_phdr(5, 2, 6, dynamic_offset, dynamic_vaddr, dynamic_size, dynamic_size, 8)

    buf[note_offset:note_offset + note_size] = build_id_data
    buf[dynstr_offset:dynstr_offset + dynstr_size] = dynstr

    def write_sym(idx, st_name, st_info, st_other, st_shndx, st_value, st_size):
        off = dynsym_offset + idx * 24
        struct.pack_into('<IBBHQQ', buf, off, st_name, st_info, st_other, st_shndx, st_value, st_size)

    RODATA_SHNDX = 5; TEXT_SHNDX = 6; BUILDID_SHNDX = 1
    STB_GLOBAL = 1; STT_OBJECT = 1; STT_FUNC = 2

    write_sym(0, 0, 0, 0, 0, 0, 0)
    write_sym(1, dynstr_name_offsets['_kDartVmSnapshotInstructions'],
              (STB_GLOBAL << 4) | STT_FUNC, 0, TEXT_SHNDX,
              sym_values['_kDartVmSnapshotInstructions'],
              sym_offsets['_kDartVmSnapshotInstructions']['size'])
    write_sym(2, dynstr_name_offsets['_kDartIsolateSnapshotInstructions'],
              (STB_GLOBAL << 4) | STT_FUNC, 0, TEXT_SHNDX,
              sym_values['_kDartIsolateSnapshotInstructions'],
              sym_offsets['_kDartIsolateSnapshotInstructions']['size'])
    write_sym(3, dynstr_name_offsets['_kDartVmSnapshotData'],
              (STB_GLOBAL << 4) | STT_OBJECT, 0, RODATA_SHNDX,
              sym_values['_kDartVmSnapshotData'],
              sym_offsets['_kDartVmSnapshotData']['size'])
    write_sym(4, dynstr_name_offsets['_kDartIsolateSnapshotData'],
              (STB_GLOBAL << 4) | STT_OBJECT, 0, RODATA_SHNDX,
              sym_values['_kDartIsolateSnapshotData'],
              sym_offsets['_kDartIsolateSnapshotData']['size'])
    write_sym(5, dynstr_name_offsets['_kDartSnapshotBuildId'],
              (STB_GLOBAL << 4) | STT_OBJECT, 0, BUILDID_SHNDX, note_offset, note_size)

    def elf_hash(name):
        h = 0
        for c in name.encode():
            h = (h << 4) + c
            g = h & 0xf0000000
            if g:
                h ^= g >> 24
            h &= ~g
        return h

    hash_off = hash_offset
    struct.pack_into('<II', buf, hash_off, nbucket, nchain)
    hash_off += 8
    bucket_off = hash_off
    chain_off = bucket_off + nbucket * 4
    sym_names_ordered = ['', '_kDartVmSnapshotInstructions', '_kDartIsolateSnapshotInstructions',
                         '_kDartVmSnapshotData', '_kDartIsolateSnapshotData', '_kDartSnapshotBuildId']

    for i, name in enumerate(sym_names_ordered):
        if not name:
            continue
        bucket_idx = elf_hash(name) % nbucket
        cur = struct.unpack_from('<I', buf, bucket_off + bucket_idx * 4)[0]
        if cur == 0:
            struct.pack_into('<I', buf, bucket_off + bucket_idx * 4, i)
        else:
            prev = cur
            while True:
                next_val = struct.unpack_from('<I', buf, chain_off + prev * 4)[0]
                if next_val == 0:
                    struct.pack_into('<I', buf, chain_off + prev * 4, i)
                    break
                prev = next_val

    buf[rodata_offset:rodata_offset + rodata_size] = rodata_data
    if text_offset + text_size > len(buf):
        buf.extend(b'\x00' * (text_offset + text_size - len(buf)))
    buf[text_offset:text_offset + text_size] = text_data

    if dynamic_offset + dynamic_size > len(buf):
        buf.extend(b'\x00' * (dynamic_offset + dynamic_size + bss_size - len(buf)))
    for i, (tag, val) in enumerate(dynamic_entries):
        struct.pack_into('<QQ', buf, dynamic_offset + i * 16, tag, val)

    needed = shdr_offset + shdr_count * shdr_entry_size
    if needed > len(buf):
        buf.extend(b'\x00' * (needed - len(buf)))
    buf[shstrtab_offset:shstrtab_offset + shstrtab_size] = shstrtab

    def write_shdr(idx, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                   sh_link=0, sh_info=0, sh_addralign=1, sh_entsize=0):
        # Elf64_Shdr layout (64 bytes):
        #   uint32 sh_name       4
        #   uint32 sh_type       4
        #   uint64 sh_flags      8
        #   uint64 sh_addr       8
        #   uint64 sh_offset     8
        #   uint64 sh_size       8
        #   uint32 sh_link       4
        #   uint32 sh_info       4
        #   uint64 sh_addralign  8
        #   uint64 sh_entsize    8   = 64 bytes total
        off = shdr_offset + idx * shdr_entry_size
        # Ensure buf is large enough
        needed = off + shdr_entry_size
        if needed > len(buf):
            buf.extend(b'\x00' * (needed - len(buf)))
        struct.pack_into('<IIQQQQ II QQ', buf, off,
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
            sh_link, sh_info, sh_addralign, sh_entsize)

    SHT_NULL=0; SHT_PROGBITS=1; SHT_STRTAB=3; SHT_NOTE=7
    SHT_DYNAMIC=6; SHT_DYNSYM=11; SHT_HASH=5; SHT_NOBITS=8
    SHF_WRITE=1; SHF_ALLOC=2; SHF_EXECINSTR=4

    write_shdr(0, 0, SHT_NULL, 0, 0, 0, 0)
    write_shdr(1, SH_NAME_BUILDID, SHT_NOTE, SHF_ALLOC, note_offset, note_offset, note_size, sh_addralign=4)
    write_shdr(2, SH_NAME_DYNSTR, SHT_STRTAB, SHF_ALLOC, dynstr_offset, dynstr_offset, dynstr_size)
    write_shdr(3, SH_NAME_DYNSYM, SHT_DYNSYM, SHF_ALLOC, dynsym_offset, dynsym_offset, dynsym_size,
               sh_link=2, sh_info=1, sh_addralign=8, sh_entsize=24)
    write_shdr(4, SH_NAME_HASH, SHT_HASH, SHF_ALLOC, hash_offset, hash_offset, hash_size,
               sh_link=3, sh_addralign=4, sh_entsize=4)
    write_shdr(5, SH_NAME_RODATA, SHT_PROGBITS, SHF_ALLOC, rodata_vaddr, rodata_offset, rodata_size, sh_addralign=64)
    write_shdr(6, SH_NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text_vaddr, text_offset, text_size, sh_addralign=64)
    write_shdr(7, SH_NAME_DYNAMIC, SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC, dynamic_vaddr, dynamic_offset, dynamic_size,
               sh_link=2, sh_addralign=8, sh_entsize=16)
    write_shdr(8, SH_NAME_BSS, SHT_PROGBITS, SHF_WRITE | SHF_ALLOC, bss_vaddr, dynamic_offset + dynamic_size, bss_size)
    write_shdr(9, SH_NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstrtab_offset, shstrtab_size)

    with open(output_path, 'wb') as f:
        f.write(buf)
    
    print(f"  Written ELF: {output_path}")
    print(f"  .text: vaddr=0x{text_vaddr:x} size=0x{text_size:x}")
    print(f"  .rodata: vaddr=0x{rodata_vaddr:x} size=0x{rodata_size:x}")
    for name, val in sym_values.items():
        print(f"  {name}: 0x{val:x}")
