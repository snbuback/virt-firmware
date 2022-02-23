#!/usr/bin/python
import os
import sys
import lzma
import uuid
import struct
import optparse

def parse_guid(data, offset):
    guid = uuid.UUID(bytes_le = data[offset:offset+16])
    name = guid.urn.split(":")[2]
    if name == "ee4e5898-3914-4259-9d6e-dc7bd79403cf":
        return "guid:LzmaCompress"
    if name == "8c8ce578-8a3d-4f1c-9935-896185c32dd3":
        return "guid:Ffs"
    if name == "9e21fd93-9c72-4c15-8c4b-e77f1db2d792":
        return "guid:FvMainCompact"
    if name == "fff12b8d-7696-4c8b-a985-2747075b4f50":
        return "guid:NvData"
    if name == "aaf32c78-947b-439a-a180-2e144ec37792":
        return "guid:AuthVars"
    if name == "df1ccef6-f301-4a63-9661-fc6030dcc880":
        return "guid:SecMain"
    if name == "1ba0062e-c779-4582-8566-336ae8f78f09":
        return "guid:ResetVector"
    if name == "96b582de-1fb2-45f7-baea-a366c55a082d":
        return "guid:OvmfGuidList"
    if name == "7255371f-3a3b-4b04-927b-1da6efa8d454":
        return "guid:SevHashTableBlock"
    if name == "4c2eb361-7d9b-4cc3-8081-127c90d3d294":
        return "guid:SevSecretBlock"
    if name == "00f771de-1a7e-4fcb-890e-68c77e2fb44e":
        return "guid:SevProcessorReset"
    if name == "dc886566-984a-4798-a75e-5585a7bf67cc":
        return "guid:OvmfSevMetadataOffset"
    if name == "e47a6535-984a-4798-865e-4685a7bf8ec2":
        return "guid:TdxMetadataOffset"
    if name == "ffffffff-ffff-ffff-ffff-ffffffffffff":
        return "guid:NotValid"
    return name

def parse_unicode(data, offset):
    pos = offset
    ascii = ""
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        if unichar[0] == 0:
            break
        if unichar[0] >= 128:
            ascii += "?"
        else:
            ascii += "%c" % unichar[0]
        pos += 2
    return ascii

def parse_sev_type(type):
    if type == 1:
        return "MEM";
    if type == 2:
        return "Secrets";
    if type == 3:
        return "CPUID";
    return "%d" % type

def parse_tdx_type(type):
    if type == 0:
        return "BFV (code)";
    if type == 1:
        return "CFV (vars)";
    if type == 2:
        return "TD Hob";
    if type == 3:
        return "MEM";
    return "%d" % type

def print_hexdump(data, start, end, indent):
    hex = ""
    ascii = ""
    pos = start
    count = 0
    while True:
        hex += "%02x " % data[start+count]
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            ascii += "%c" % data[start+count]
        else:
            ascii += "."
        count += 1
        if count % 4 == 0:
            hex += " "
            ascii += " "
        if count % 16 == 0 or start+count == end:
            print("%06x: %*s%-52s %s" % (pos, indent, "", hex, ascii))
            hex = ""
            ascii = ""
            pos += 16
        if count == 64 or start+count == end:
            break

def print_sections(data, start, end, indent):
    pos = start
    while True:
        pos = (pos + 3) & ~3; # align
        (s1, s2, s3, type, xsize) = struct.unpack_from("=BBBBL", data, pos)
        size = s1 | (s2 << 8) | (s3 << 16)
        hlen = 4
        if size == 0xffffffff: # large section
            size = xsize
            hlen = 8

        if size == 0:
            print("%06x: %*sstop: section size is zero" % (pos, indent, ""))
            break
        if pos + size > end:
            print("%06x: %*sstop: section size is too big (0x%x + 0x%x > 0x%x)" %
                  (pos, indent, "", pos, size, end))
            break

        extra = ""
        guid = ""
        if type == 0x02: # guid defined
            guid = parse_guid(data, pos + hlen)
            (doff, attr) = struct.unpack_from("=HH", data, pos + hlen + 16)
            extra += " [ subtype=%s doff=0x%x attr=0x%x ]" % (guid, doff, attr)
        if type == 0x10: # pe32
            extra += " [ pe32 ]"
        if type == 0x13: # depex
            extra += " [ dxe depex ]"
        if type == 0x14: # version
            build = struct.unpack_from("=H", data, pos + hlen)
            name = parse_unicode(data, pos + hlen + 2)
            extra += " [ build=%d version=%s ]" % (build[0], name)
        if type == 0x15: # user interface
            name = parse_unicode(data, pos + hlen)
            extra += " [ name=%s ]" % (name)
        if type == 0x17: # firmware volume
            extra += " [ firmware volume ]"
        if type == 0x19: # raw
            name = parse_unicode(data, pos + hlen)
            extra += " [ raw ]"
        if type == 0x1b: # pei depex
            extra += " [ pei depex ]"
        if type == 0x1c: # smm depex
            extra += " [ smm depex ]"

        print("%06x: %*ssection type=0x%x size=0x%x%s" %
              (pos, indent, "", type, size, extra))

        if guid == "guid:LzmaCompress":
            unxz = lzma.decompress(data[pos+doff:pos+size])
            print("--xz--: %*scompressed sections follow" % (indent, ""))
            print_sections(unxz, 0, len(unxz), indent + 2)
            print("--xz--: %*send" % (indent, ""))
        if type == 0x17: # firmware volume
            print_one_volume(data, pos + hlen, indent + 1)

        pos += size
        if pos >= end:
            break

def print_var(data, offset, indent):
    (id, state, attr, count) = struct.unpack_from("=HBxLQ", data, offset)
    if id != 0x55aa:
        return 0
    (pk, nsize, dsize) = struct.unpack_from("=LLL", data, offset + 32)
    guid = parse_guid(data, offset + 44)
    name = parse_unicode(data, offset + 44 + 16)
    print("%06x: %*svar state=0x%x attr=0x%x nsize=0x%x dsize=0x%x [ %s ]" %
          (offset, indent, "", state, attr, nsize, dsize, name))
    start = offset + 44 + 16 + nsize
    if state == 0x3f:
        print_hexdump(data, start, start + dsize, indent+2)
    return start - offset + dsize
    
def print_varstore(data, start, end, indent):
    guid = parse_guid(data, start)
    (size, format, state) = struct.unpack_from("=LBB", data, start + 16)
    print("%06x: %*svarstore=%s size=0x%x format=0x%x state=0x%x" %
          (start, indent, "", guid, size, format, state))
    pos = start + 16 + 12
    while True:
        pos = (pos + 3) & ~3; # align
        vsize = print_var(data, pos, indent+2)
        if vsize == 0:
            break;
        pos += vsize
        if pos >= start + size:
            break
    return size

def print_resetvector(data, start, end, indent):
    sevpos = 0
    tdxpos = 0
    pos = end - 0x20
    guid = parse_guid(data, pos - 0x10);
    if guid != "guid:OvmfGuidList":
        return
    size = struct.unpack_from("=H", data, pos - 0x12)
    start = pos - size[0]
    print("%06x: %*sguid=%s totalsize=0x%x" %
          (pos, indent, "", guid, size[0]))
    pos -= 0x12
    while pos - 0x12 >= start:
        guid = parse_guid(data, pos - 0x10);
        size = struct.unpack_from("=H", data, pos - 0x12)
        print("%06x: %*sguid=%s size=0x%x" %
              (pos - 0x12, indent, "", guid, size[0]))
        print_hexdump(data, pos - size[0], pos - 0x12, indent + 2)
        if guid == "guid:OvmfSevMetadataOffset":
            offset = struct.unpack_from("=L", data, pos - size[0])
            sevpos = end - offset[0]
        if guid == "guid:TdxMetadataOffset":
            offset = struct.unpack_from("=L", data, pos - size[0])
            tdxpos = end - offset[0]
        pos -= size[0]

    if sevpos:
        (magic, size, version, entries) = struct.unpack_from("=LLLL", data, sevpos)
        print("%06x: %*ssev: size=0x%x version=%d entries=%d" %
              (sevpos, indent, "", size, version, entries))
        for i in range(entries):
            (base, size, type) = struct.unpack_from(
                "=LLL", data, sevpos + 16 + i * 12)
            print("%06x: %*sbase=0x%x size=0x%x type=%s" %
                  (sevpos + 16 + i * 12, indent + 2, "",
                   base, size, parse_sev_type(type)))

    if tdxpos:
        (magic, size, version, entries) = struct.unpack_from("=LLLL", data, tdxpos)
        print("%06x: %*stdx: size=0x%x version=%d entries=%d" %
              (tdxpos, indent, "", size, version, entries))
        for i in range(entries):
            (filebase, filesize, membase, memsize, type, flags) = struct.unpack_from(
                "=LLQQLL", data, tdxpos + 16 + i * 32)
            print("%06x: %*sfbase=0x%x fsize=0x%x mbase=0x%x msize=0x%x type=%s, flags=0x%x" %
                  (tdxpos + 16 + i * 32, indent + 2, "",
                   filebase, filesize, membase, memsize,
                   parse_tdx_type(type), flags))

def print_one_file(data, offset, indent):
    guid = parse_guid(data, offset)
    (type, attr, s1, s2, s3, state, xsize) = struct.unpack_from("=xxBBBBBBL", data, offset + 16)
    if attr & 0x01: # large file
        size = xsize
        hlen = 12
    else:
        size = s1 | (s2 << 8) | (s3 << 16);
        hlen = 8

    typename = "0x%x" % type
    sections = False
    if type == 0xf0:
        typename = "padding"
    if type == 0x02:
        typename = "freeform"
        sections = True
    if type == 0x03:
        typename = "sec-core"
        sections = True
    if type == 0x04:
        typename = "pei-core"
        sections = True
    if type == 0x05:
        typename = "dxe-core"
        sections = True
    if type == 0x06:
        typename = "peim"
        sections = True
    if type == 0x07:
        typename = "driver"
        sections = True
    if type == 0x09:
        typename = "application"
        sections = True
    if type == 0x0a:
        typename = "smm"
        sections = True
    if type == 0x0b:
        typename = "fw-volume"
        sections = True

    print("%06x: %*sfile=%s type=%s size=0x%x" %
          (offset, indent, "", guid, typename, size))
    if sections:
        print_sections(data,
                       offset + 16 + hlen,
                       offset + size,
                       indent + 2)
    if guid == "guid:ResetVector":
        print_resetvector(data,
                          offset + 16 + hlen,
                          offset + size,
                          indent + 2)
    return size

def print_all_files(data, start, end, indent):
    pos = start
    size = 0
    while True:
        pos = (pos + size + 7) & ~7; # align
        if pos + 16 >= end:
            break
        size = print_one_file(data, pos, indent)
    
def print_one_volume(data, offset, indent):
    guid = parse_guid(data, offset + 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = struct.unpack_from("=QLLHHHxBLL", data, offset + 32)
    print("%06x: %*svol=%s vlen=0x%x rev=%d blocks=%dx%d (0x%x)" %
          (offset, indent, "", guid, vlen, rev, blocks, blksize, blocks * blksize))
    if guid == "guid:Ffs":
        print_all_files(data,
                        offset + hlen,
                        offset + blocks * blksize,
                        indent + 2)
    if guid == "guid:NvData":
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
            print("%06x: %*sstop: volume size is zero" % (pos, indent, ""))
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
        exit(1)

    file = open(options.input, "rb");
    data = file.read()
    file.close()
    print_all_volumes(data, 0)

if __name__ == '__main__':
    sys.exit(main())
