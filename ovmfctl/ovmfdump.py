#!/usr/bin/python
""" dump content of ovmf firmware volumes """
import sys
import lzma
import struct
import optparse

from ovmfctl.efi import guids

def parse_unicode(data, offset):
    pos = offset
    name = ""
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        if unichar[0] == 0:
            break
        if unichar[0] >= 128:
            name += "?"
        else:
            name += f'{unichar[0]:c}'
        pos += 2
    return name

def parse_sev_type(typeid):
    if typeid == 1:
        return "MEM"
    if typeid == 2:
        return "Secrets"
    if typeid == 3:
        return "CPUID"
    return f'{typeid}'

def parse_tdx_type(typeid):
    if typeid == 0:
        return "BFV (code)"
    if typeid == 1:
        return "CFV (vars)"
    if typeid == 2:
        return "TD Hob"
    if typeid == 3:
        return "MEM"
    return f'{typeid}'

def print_hexdump(data, start, end, indent):
    hstr = ""
    astr = ""
    pos = start
    count = 0
    while True:
        hstr += f'{data[start+count]:02x} '
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            astr += f'{data[start+count]:c}'
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

        extra = ""
        guid = ""
        if typeid == 0x02: # guid defined
            guid = guids.parse(data, pos + hlen)
            (doff, attr) = struct.unpack_from("=HH", data, pos + hlen + 16)
            extra += f' [ subtype={guids.name(guid)} doff=0x{doff:x} attr=0x{attr:x} ]'
        if typeid == 0x10: # pe32
            extra += " [ pe32 ]"
        if typeid == 0x13: # depex
            extra += " [ dxe depex ]"
        if typeid == 0x14: # version
            build = struct.unpack_from("=H", data, pos + hlen)
            name = parse_unicode(data, pos + hlen + 2)
            extra += f' [ build={build[0]} version={name} ]'
        if typeid == 0x15: # user interface
            name = parse_unicode(data, pos + hlen)
            extra += f' [ name={name} ]'
        if typeid == 0x17: # firmware volume
            extra += " [ firmware volume ]"
        if typeid == 0x19: # raw
            name = parse_unicode(data, pos + hlen)
            extra += " [ raw ]"
        if typeid == 0x1b: # pei depex
            extra += " [ pei depex ]"
        if typeid == 0x1c: # smm depex
            extra += " [ smm depex ]"

        print(f'{pos:06x}: {"":{indent}s}section '
              f'type=0x{typeid:x} size=0x{size:x}{extra}')

        if guid == guids.LzmaCompress:
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
    guid = guids.parse(data, offset + 44)
    name = parse_unicode(data, offset + 44 + 16)
    print(f'{offset:06x}: {"":{indent}s}var state=0x{state:x} '
          f'attr=0x{attr:x} nsize=0x{nsize:x} dsize=0x{dsize:x} [ {name} ]')
    start = offset + 44 + 16 + nsize
    if state == 0x3f:
        print_hexdump(data, start, start + dsize, indent+2)
    return start - offset + dsize

def print_varstore(data, start, end, indent):
    guid = guids.parse(data, start)
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
    return size

def print_resetvector(data, start, end, indent):
    sevpos = 0
    tdxpos = 0
    pos = end - 0x20
    guid = guids.parse(data, pos - 0x10)
    if guid != guids.OvmfGuidList:
        return
    size = struct.unpack_from("=H", data, pos - 0x12)
    start = pos - size[0]
    print(f'{pos:06x}: {"":{indent}s}'
          f'guid={guids.name(guid)} totalsize=0x{size[0]:x}')
    pos -= 0x12
    while pos - 0x12 >= start:
        guid = guids.parse(data, pos - 0x10)
        size = struct.unpack_from("=H", data, pos - 0x12)
        print(f'{pos - 0x12:06x}: {"":{indent}s}'
              f'guid={guids.name(guid)} size=0x{size[0]:x}')
        print_hexdump(data, pos - size[0], pos - 0x12, indent + 2)
        if guid == guids.OvmfSevMetadataOffset:
            offset = struct.unpack_from("=L", data, pos - size[0])
            sevpos = end - offset[0]
        if guid == guids.TdxMetadataOffset:
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

def print_one_file(data, offset, indent):
    guid = guids.parse(data, offset)
    (typeid, attr, s1, s2, s3, state, xsize) = struct.unpack_from("=xxBBBBBBL", data, offset + 16)
    if attr & 0x01: # large file
        size = xsize
        hlen = 12
    else:
        size = s1 | (s2 << 8) | (s3 << 16)
        hlen = 8

    typename = f'0x{typeid:x}'
    sections = False
    if typeid == 0xf0:
        typename = "padding"
    if typeid == 0x02:
        typename = "freeform"
        sections = True
    if typeid == 0x03:
        typename = "sec-core"
        sections = True
    if typeid == 0x04:
        typename = "pei-core"
        sections = True
    if typeid == 0x05:
        typename = "dxe-core"
        sections = True
    if typeid == 0x06:
        typename = "peim"
        sections = True
    if typeid == 0x07:
        typename = "driver"
        sections = True
    if typeid == 0x09:
        typename = "application"
        sections = True
    if typeid == 0x0a:
        typename = "smm"
        sections = True
    if typeid == 0x0b:
        typename = "fw-volume"
        sections = True

    print(f'{offset:06x}: {"":{indent}s}vol={guids.name(guid)} '
          f'type={typename} size=0x{size:x}')
    if sections:
        print_sections(data,
                       offset + 16 + hlen,
                       offset + size,
                       indent + 2)
    if guid == guids.ResetVector:
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
    guid = guids.parse(data, offset + 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
        struct.unpack_from("=QLLHHHxBLL", data, offset + 32)
    print(f'{offset:06x}: {"":{indent}s}vol={guids.name(guid)} '
          f'vlen=0x{vlen:x} rev={rev} blocks={blocks}*{blksize} '
          f'(0x{blocks * blksize:x})')
    if guid == guids.Ffs:
        print_all_files(data,
                        offset + hlen,
                        offset + blocks * blksize,
                        indent + 2)
    if guid == guids.NvData:
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
            print(f'{pos:06x}: {"":{indent}s}stop: volume size is zero')
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
