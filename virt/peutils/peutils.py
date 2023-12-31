#!/usr/bin/python3
""" pe (efi) binary utilities """
import sys
import struct
import argparse

import pefile

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from virt.firmware.efi import guids
from virt.firmware.efi import siglist

def common_name(item):
    try:
        scn = item.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        return scn.value
    except IndexError:
        return 'no CN'

def is_ca_cert(cert):
    try:
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    except x509.extensions.ExtensionNotFound:
        bc = False
    if bc:
        return bc.value.ca
    return False

def print_cert(cert, ii, verbose = False):
    print(f'# {ii}   certificate')
    if verbose:
        print(f'# {ii}      subject: {cert.subject.rfc4514_string()}')
        print(f'# {ii}      issuer : {cert.issuer.rfc4514_string()}')
        print(f'# {ii}      valid  : {cert.not_valid_before} -> {cert.not_valid_after}')
        print(f'# {ii}      CA     : {is_ca_cert(cert)}')
    else:
        scn = common_name(cert.subject)
        icn = common_name(cert.issuer)
        print(f'# {ii}      subject CN: {scn}')
        print(f'# {ii}      issuer  CN: {icn}')

def print_vendor_cert(db, ii, verbose = False):
    # VENDOR_CERT_FILE
    try:
        crt = x509.load_der_x509_certificate(db, default_backend())
        print_cert(crt, ii, verbose)
        return
    except ValueError:
        pass

    # VENDOR_DB_FILE
    sigdb = siglist.EfiSigDB(db)
    for sl in sigdb:
        if str(sl.guid) == guids.EfiCertX509:
            print_cert(sl.x509, ii, verbose)
        elif str(sl.guid) == guids.EfiCertSha256:
            print(f'# {ii}   sha256')
            print(f'# {ii}      {len(sl)} entries')
        else:
            print(f'# {ii}   {sl.guid}')

def print_sbat_entries(ii, name, data):
    print(f'# {ii}{name}')
    entries = data.decode().rstrip('\n').split('\n')
    for entry in entries:
        print(f'# {ii}   {entry}')

def sig_type2(data, ii, extract = False, verbose = False):
    certs = pkcs7.load_der_pkcs7_certificates(data)
    for cert in certs:
        print_cert(cert, ii, verbose)

        if extract:
            scn = common_name(cert.subject)
            fn = "".join(x for x in scn if x.isalnum()) + '.pem'
            print(f'# {ii}      >>> {fn}')
            with open(fn, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

def getcstr(data):
    """ get C string (terminated by null byte) """
    idx = 0
    for b in data:
        if b == 0:
            break
        idx += 1
    return data[:idx]

def pe_string(pe, index):
    """ lookup string in string table (right after symbol table) """
    strtab  = pe.FILE_HEADER.PointerToSymbolTable
    strtab += pe.FILE_HEADER.NumberOfSymbols * 18
    strtab += index
    return getcstr(pe.__data__[strtab:])

def pe_section_flags(sec):
    r = '-'
    w = '-'
    x = '-'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']:
        r = 'r'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:
        w = 'w'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
        x = 'x'
    return r + w + x

def pe_print_sigs(filename, pe, indent, extract, verbose):
    i  = f'{"":{indent}s}'
    ii = f'{"":{indent+3}s}'
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sighdr.VirtualAddress and sighdr.Size:
        print(f'# {i}sigdata:'
              f' addr 0x{sighdr.VirtualAddress:08x} +0x{sighdr.Size:08x}')
        sigs = pe.__data__[ sighdr.VirtualAddress :
                            sighdr.VirtualAddress + sighdr.Size ]
        pos = 0
        index = 0
        while pos + 8 < len(sigs):
            (slen, srev, stype) = struct.unpack_from('<LHH', sigs, pos)
            print(f'# {ii}signature: len 0x{slen:x}, type 0x{stype:x}')
            if extract:
                index += 1
                fn = filename.split('/')[-1] + f'.sig{index}'
                print(f'# {ii}>>> {fn}')
                with open(fn, 'wb') as f:
                    f.write(sigs [ pos : pos + slen ])
            if stype == 2:
                sig_type2(sigs [ pos + 8 : pos + slen ],
                          ii, extract, verbose)
            pos += slen
            pos = (pos + 7) & ~7 # align

# pylint: disable=too-many-branches
def pe_print_section(pe, sec, indent, verbose):
    i  = f'{"":{indent}s}'
    ii = f'{"":{indent+3}s}'
    if sec.Name.startswith(b'/'):
        idx = getcstr(sec.Name[1:])
        sec.Name = pe_string(pe, int(idx))
    print(f'# {i}section:'
          f' file 0x{sec.PointerToRawData:08x} +0x{sec.SizeOfRawData:08x}'
          f'  virt 0x{sec.VirtualAddress:08x} +0x{sec.Misc_VirtualSize:08x}'
          f'  {pe_section_flags(sec)} ({sec.Name.decode()})')
    if sec.Name == b'.vendor_cert':
        vcert = sec.get_data()
        (dbs, dbxs, dbo, dbxo) = struct.unpack_from('<IIII', vcert)
        if dbs:
            print(f'# {ii}db: {dbo} +{dbs}')
            db = vcert [ dbo : dbo + dbs ]
            print_vendor_cert(db, ii, verbose)
        if dbxs:
            print(f'# {ii}dbx: {dbxo} +{dbxs}')
            dbx = vcert [ dbxo : dbxo + dbxs ]
            print_vendor_cert(dbx, ii, verbose)
    if sec.Name == b'.sbatlevel':
        levels = sec.get_data()
        (version, poff, loff) = struct.unpack_from('<III', levels)
        print_sbat_entries(ii, 'previous', getcstr(levels[poff + 4:]))
        print_sbat_entries(ii, 'latest', getcstr(levels[loff + 4:]))
    if sec.Name in (b'.sdmagic', b'.data.ident', b'.cmdline',
                    b'.uname\0\0', b'.sbat\0\0\0'):
        lines = sec.get_data().decode().rstrip('\n\0')
        for line in lines.split('\n'):
            print(f'# {ii}{line}')
    if sec.Name == b'.osrel\0\0':
        osrel = sec.get_data().decode().rstrip('\n\0')
        entries = osrel.split('\n')
        for entry in entries:
            if entry.startswith('PRETTY_NAME'):
                print(f'# {ii}{entry}')
    if sec.Name == b'.linux\0\0':
        print(f'# {ii}embedded binary')
        try:
            npe = pefile.PE(data = sec.get_data())
            for nsec in npe.sections:
                pe_print_section(npe, nsec, indent + 6, verbose)
            pe_print_sigs(None, npe, indent + 6, False, verbose)
        except pefile.PEFormatError:
            print(f'# {ii}   not a PE binary')

def efi_binary(filename, extract = False, verbose = False):
    print(f'# file: {filename}')
    try:
        pe = pefile.PE(filename)
        for sec in pe.sections:
            pe_print_section(pe, sec, 3, verbose)
        pe_print_sigs(filename, pe, 3, extract, verbose)
    except pefile.PEFormatError:
        print('#    not a PE binary')

def read_sig(filename):
    print(f'# <<< {filename} (signature)')
    with open(filename, 'rb') as f:
        blob = f.read()
    while len(blob) & 7:
        blob += b'\0'
    return blob

def efi_addsig(infile, outfile, sigfiles, replace = False):
    print(f'# <<< {infile} (efi binary)')
    pe = pefile.PE(infile)
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    addr = sighdr.VirtualAddress
    size = sighdr.Size

    if addr:
        print(f'#    addr: 0x{addr:06x} +0x{size:06x} (existing sigs)')
        copy = addr + size
    else:
        addr = len(pe.__data__)
        copy = addr
        soze = 0
        print(f'#    addr: 0x{addr:06x} (no sigs, appending)')

    if size and replace:
        print('#    drop existing sigs')
        copy = addr
        size = 0

    addsigs = b''
    if sigfiles:
        for sigfile in sigfiles:
            blob = read_sig(sigfile)
            print(f'#    add sig (+0x{len(blob):06x})')
            addsigs += blob
            size += len(blob)

    if outfile:
        print(f'# >>> {outfile} (efi binary)')
        with open(outfile, 'wb') as f:
            print(f'#    fixup addr: 0x{addr:06x} +0x{size:06x} ')
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = addr
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = size
            print(f'#    copy: 0x{copy:06x} bytes')
            f.write(pe.write()[ : copy ])
            if len(addsigs):
                print(f'#    addsigs: 0x{len(addsigs):06x} bytes')
                f.write(addsigs)

def pe_dumpinfo():
    parser = argparse.ArgumentParser()
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()
    for filename in options.FILES:
        print(f'# file: {filename}')
        pe = pefile.PE(filename)
        print(pe.dump_info())
    return 0

def pe_listsigs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-x', '--extract', dest = 'extract',
                        action = 'store_true', default = False,
                        help = 'also extract signatures and certificates')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more certificate details')
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()
    for filename in options.FILES:
        efi_binary(filename, options.extract, options.verbose)
    return 0

def pe_addsigs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', dest = 'infile', type = str,
                        help = 'read efi binary from FILE', metavar = 'FILE')
    parser.add_argument('-o', '--output', dest = 'outfile', type = str,
                        help = 'write efi binary to FILE', metavar = 'FILE')
    parser.add_argument('-s', '--addsig', dest = 'addsigs',
                        type = str, action = 'append',
                        help = 'append  detached signature from FILE',
                        metavar = 'FILE')
    parser.add_argument('--replace', dest = 'replace',
                        action = 'store_true', default = False,
                        help = 'replace existing signatures')
    options = parser.parse_args()

    if not options.infile:
        print('missing input file (try --help)')
        return 1

    efi_addsig(options.infile, options.outfile, options.addsigs, options.replace)
    return 0

if __name__ == '__main__':
    sys.exit(pe_listsigs())
