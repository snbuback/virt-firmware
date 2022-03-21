#!/usr/bin/python
""" dump content of ovmf firmware volumes """
import sys
import lzma
import struct
import optparse

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16

def parse_sev_type(typeid):
    id2name = {
        1 : "NEN",
        2 : "Secrets",
        3 : "CPUID",
    }
    return id2name.get(typeid, f'{typeid}')

def parse_tdx_type(typeid):
    id2name = {
        0 : "BFV (code)",
        1 : "CFV (vars)",
        2 : "TD Hob",
        3 : "MEM",
    }
    return id2name.get(typeid, f'{typeid}')

def print_hexdump(data, start, end, indent):
    hstr = ""
    astr = ""
    pos = start
    count = 0
    while True:
        hstr += f"{data[start+count]:02x} "
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            astr += f"{data[start+count]:c}"
        else:
            astr += "."
        count += 1
        if count % 4 == 0:
            hstr += " "
            astr += " "
        if count % 16 == 0 or start+count == end:
            print(f'{pos:06x}: {"":{indent}s}{hstr:52s} {astr}')
            hstr = ""
            astr = ""
            pos += 16
        if count == 64 or start+count == end:
            break

def section_desc(data, start, typeid):
    id2name = {
        0x10 : "pe32",
        0x13 : "dxe depex",
        0x17 : "firmware volume",
        0x19 : "raw",
        0x1b : "pei depex",
        0x1c : "smm depex",
    }
    if id2name.get(typeid):
        return f' [ {id2name.get(typeid)} ]'
    if typeid == 0x02: # guid defined
        guid = guids.parse_bin(data, start)
        (doff, attr) = struct.unpack_from("=HH", data, start + 16)
        return f' [ subtype={guids.name(guid)} doff=0x{doff:x} attr=0x{attr:x} ]'
    if typeid == 0x14: # version
        build = struct.unpack_from("=H", data, start)
        name = ucs16.from_ucs16(data, start + 2)
        return f' [ build={build[0]} version={name} ]'
    if typeid == 0x15: # user interface
        name = ucs16.from_ucs16(data, start)
        return f' [ name={name} ]'
    return ""

def print_sections(data, start, end, indent):
    pos = start
    while True:
        pos = (pos + 3) & ~3    # align
        (s1, s2, s3, typeid, xsize) = struct.unpack_from("=BBBBL", data, pos)
        size = s1 | (s2 << 8) | (s3 << 16)
        hlen = 4
        if size == 0xffffffff:  # large section
            size = xsize
            hlen = 8

        if size == 0:
            print(f'{pos:06x}: {"":{indent}s}stop: section size is zero')
            break
        if pos + size > end:
            print(f'{pos:06x}: {"":{indent}s}stop: section size is '
                  f'too big (0x{pos:x} + 0x{size:x} > 0x{end:x})')
            break

        extra = section_desc(data, pos + hlen, typeid)
        print(f'{pos:06x}: {"":{indent}s}section '
              f'type=0x{typeid:x} size=0x{size:x}{extra}')

        if typeid == 0x02: # guid defined
            guid = guids.parse_bin(data, pos + hlen)
            (doff, attr) = struct.unpack_from("=HH", data, pos + hlen + 16)
            if str(guid) == guids.LzmaCompress:
                unxz = lzma.decompress(data[pos+doff:pos+size])
                print(f'--xz--: {"":{indent}s}compressed sections follow')
                print_sections(unxz, 0, len(unxz), indent + 2)
                print(f'--xz--: {"":{indent}s}end')
        if typeid == 0x17: # firmware volume
            print_one_volume(data, pos + hlen, indent + 1)

        pos += size
        if pos >= end:
            break

def print_var(data, offset, indent):
    (magic, state, attr, count) = struct.unpack_from("=HBxLQ", data, offset)
    if magic != 0x55aa:
        return 0
    (pk, nsize, dsize) = struct.unpack_from("=LLL", data, offset + 32)
    guid = guids.parse_bin(data, offset + 44)
    name = ucs16.from_ucs16(data, offset + 44 + 16)
    print(f'{offset:06x}: {"":{indent}s}var state=0x{state:x} '
          f'attr=0x{attr:x} nsize=0x{nsize:x} dsize=0x{dsize:x} [ {name} ]')
    start = offset + 44 + 16 + nsize
    if state == 0x3f:
        print_hexdump(data, start, start + dsize, indent+2)
    return start - offset + dsize

def print_varstore(data, start, end, indent):
    guid = guids.parse_bin(data, start)
    (size, storefmt, state) = struct.unpack_from("=LBB", data, start + 16)
    print(f'{start:06x}: {"":{indent}s}varstore={guids.name(guid)} '
          f'size=0x{size:x} format=0x{storefmt:x} state=0x{state:x}')
    pos = start + 16 + 12
    while True:
        pos = (pos + 3) & ~3  # align
        vsize = print_var(data, pos, indent+2)
        if vsize == 0:
            break
        pos += vsize
        if pos >= start + size:
            break
        if pos >= end:
            break
    return size

def print_resetvector(data, start, end, indent):
    sevpos = 0
    tdxpos = 0
    pos = end - 0x20
    guid = guids.parse_bin(data, pos - 0x10)
    if str(guid) != guids.OvmfGuidList:
        return
    size = struct.unpack_from("=H", data, pos - 0x12)
    start = pos - size[0]
    print(f'{pos:06x}: {"":{indent}s}'
          f'guid={guids.name(guid)} totalsize=0x{size[0]:x}')
    pos -= 0x12
    while pos - 0x12 >= start:
        guid = guids.parse_bin(data, pos - 0x10)
        size = struct.unpack_from("=H", data, pos - 0x12)
        print(f'{pos - 0x12:06x}: {"":{indent}s}'
              f'guid={guids.name(guid)} size=0x{size[0]:x}')
        print_hexdump(data, pos - size[0], pos - 0x12, indent + 2)
        if str(guid) == guids.OvmfSevMetadataOffset:
            offset = struct.unpack_from("=L", data, pos - size[0])
            sevpos = end - offset[0]
        if str(guid) == guids.TdxMetadataOffset:
            offset = struct.unpack_from("=L", data, pos - size[0])
            tdxpos = end - offset[0]
        pos -= size[0]

    if sevpos:
        (magic, size, version, entries) = struct.unpack_from("=LLLL", data, sevpos)
        print(f'{sevpos:06x}: {"":{indent}s}sev: '
              f'size=0x{size:x} version={version} entries={entries}')
        for i in range(entries):
            (base, size, typeid) = struct.unpack_from(
                "=LLL", data, sevpos + 16 + i * 12)
            print(f'{sevpos + 16 + i * 12:06x}: {"":{indent+2}s}'
                  f'base=0x{base:x} size=0x{size:x} '
                  f'type={parse_sev_type(typeid)}')

    if tdxpos:
        (magic, size, version, entries) = struct.unpack_from("=LLLL", data, tdxpos)
        print(f'{tdxpos:06x}: {"":{indent}s}tdx: '
              f'size=0x{size:x} version={version} entries={entries}')
        for i in range(entries):
            (filebase, filesize, membase, memsize, typeid, flags) = struct.unpack_from(
                "=LLQQLL", data, tdxpos + 16 + i * 32)
            print(f'{tdxpos + 16 + i * 32:06x}: {"":{indent+2}s}'
                  f'fbase=0x{filebase:x} fsize=0x{filesize:x} '
                  f'mbase=0x{membase:x} msize=0x{memsize:x} '
                  f'type={parse_tdx_type(typeid)}, flags=0x{flags:x}')

def parse_file_type(typeid):
    id2name = {
        0x02 : "freeform",
        0x03 : "sec-core",
        0x04 : "pei-core",
        0x05 : "dxe-core",
        0x06 : "peim",
        0x07 : "driver",
        0x09 : "application",
        0x0a : "smm",
        0x0b : "fw-volume",
    }

    if id2name.get(typeid):
        return (id2name.get(typeid), True)
    if typeid == 0xf0:
        return ("padding", False)
    return (f'0x{typeid:x}', False)

def print_one_file(data, offset, indent):
    guid = guids.parse_bin(data, offset)
    (typeid, attr, s1, s2, s3, state, xsize) = struct.unpack_from("=xxBBBBBBL", data, offset + 16)
    if attr & 0x01: # large file
        size = xsize
        hlen = 12
    else:
        size = s1 | (s2 << 8) | (s3 << 16)
        hlen = 8

    (typename, sections) = parse_file_type(typeid)
    print(f'{offset:06x}: {"":{indent}s}vol={guids.name(guid)} '
          f'type={typename} size=0x{size:x}')
    if sections:
        print_sections(data,
                       offset + 16 + hlen,
                       offset + size,
                       indent + 2)
    if str(guid) == guids.ResetVector:
        print_resetvector(data,
                          offset + 16 + hlen,
                          offset + size,
                          indent + 2)
    return size

def print_all_files(data, start, end, indent):
    pos = start
    size = 0
    while True:
        pos = (pos + size + 7) & ~7  # align
        if pos + 16 >= end:
            break
        size = print_one_file(data, pos, indent)

def print_one_volume(data, offset, indent):
    guid = guids.parse_bin(data, offset + 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
        struct.unpack_from("=QLLHHHxBLL", data, offset + 32)
    print(f'{offset:06x}:{"":{indent+1}s}vol={guids.name(guid)} '
          f'vlen=0x{vlen:x} rev={rev} blocks={blocks}*{blksize} '
          f'(0x{blocks * blksize:x})')
    if str(guid) == guids.Ffs:
        print_all_files(data,
                        offset + hlen,
                        offset + blocks * blksize,
                        indent + 2)
    if str(guid) == guids.NvData:
        print_varstore(data,
                       offset + hlen,
                       offset + blocks * blksize,
                       indent + 2)
    return vlen

def print_all_volumes(data, indent):
    pos = 0
    (vlen, sig) = struct.unpack_from("=QL", data, pos + 32)
    if sig != 0x4856465f:
        pos += 0x1000  # arm/aa64 code image
    while pos < len(data):
        size = print_one_volume(data, pos, indent)
        if size == 0:
            print(f'{pos:06x}:{"":{indent+1}s}stop: volume size is zero')
            break
        pos += size

# main
def main():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'dump firmware volume FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    if not options.input:
        print("ERROR: no input file specified (try -h for help)")
        sys.exit(1)

    with open(options.input, "rb") as f:
        data = f.read()
    print_all_volumes(data, 0)

if __name__ == '__main__':
    sys.exit(main())
