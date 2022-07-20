#!/usr/bin/python3
""" pe (efi) binary utilities """
import sys
import struct
import optparse

import pefile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

def common_name(item):
    try:
        scn = item.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        return scn.value
    except IndexError:
        return 'no CN'

def is_ca_cert(cert):
    bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    if bc:
        return bc.value.ca
    return False

def print_cert_short(cert):
    scn = common_name(cert.subject)
    icn = common_name(cert.issuer)
    print(f'#             subject CN: {scn}')
    print(f'#             issuer  CN: {icn}')

def print_cert_long(cert):
    print(f'#             subject: {cert.subject.rfc4514_string()}')
    print(f'#             issuer : {cert.issuer.rfc4514_string()}')
    print(f'#             valid  : {cert.not_valid_before} -> {cert.not_valid_after}')
    print(f'#             CA     : {is_ca_cert(cert)}')

def sig_type2(data, extract = False, verbose = False):
    certs = pkcs7.load_der_pkcs7_certificates(data)
    for cert in certs:
        print('#          certificate')
        if verbose:
            print_cert_long(cert)
        else:
            print_cert_short(cert)

        if extract:
            scn = common_name(cert.subject)
            fn = "".join(x for x in scn if x.isalnum()) + '.pem'
            print(f'#             >>> {fn}')
            with open(fn, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

def efi_binary(filename, extract = False, verbose = False):
    print(f'# file: {filename}')
    pe = pefile.PE(filename)
    for sec in pe.sections:
        print(f'#    section: 0x{sec.PointerToRawData:06x} +0x{sec.SizeOfRawData:06x}'
              f' ({sec.Name.decode()})')
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sighdr.VirtualAddress and sighdr.Size:
        print(f'#    sigdata: 0x{sighdr.VirtualAddress:06x} +0x{sighdr.Size:06x}')
        sigs = pe.__data__[ sighdr.VirtualAddress :
                            sighdr.VirtualAddress + sighdr.Size ]
        pos = 0
        index = 0
        while pos + 8 < len(sigs):
            (slen, srev, stype) = struct.unpack_from('<LHH', sigs, pos)
            print(f'#       signature: len 0x{slen:x}, type 0x{stype:x}')
            if extract:
                index += 1
                fn = filename.split('/')[-1] + f'.sig{index}'
                print(f'#       >>> {fn}')
                with open(fn, 'wb') as f:
                    f.write(sigs [ pos : pos + slen ])
            if stype == 2:
                sig_type2(sigs [ pos + 8 : pos + slen ],
                          extract, verbose)
            pos += slen
            pos = (pos + 7) & ~7 # align

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
    parser = optparse.OptionParser()
    (options, args) = parser.parse_args()
    for filename in args:
        print(f'# file: {filename}')
        pe = pefile.PE(filename)
        print(pe.dump_info())
    return 0

def pe_listsigs():
    parser = optparse.OptionParser()
    parser.add_option('-x', '--extract', dest = 'extract',
                      action = 'store_true', default = False,
                      help = 'also extract signatures and certificates')
    parser.add_option('-v', '--verbose', dest = 'verbose',
                      action = 'store_true', default = False,
                      help = 'print more certificate details')
    (options, args) = parser.parse_args()
    for filename in args:
        efi_binary(filename, options.extract, options.verbose)
    return 0

def pe_addsigs():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', dest = 'infile', type = 'string',
                      help = 'read efi binary from FILE', metavar = 'FILE')
    parser.add_option('-o', '--output', dest = 'outfile', type = 'string',
                      help = 'write efi binary to FILE', metavar = 'FILE')
    parser.add_option('-s', '--addsig', dest = 'addsigs',
                      type = 'string', action = 'append',
                      help = 'append  detached signature from FILE',
                      metavar = 'FILE')
    parser.add_option('--replace', dest = 'replace',
                      action = 'store_true', default = False,
                      help = 'replace existing signatures')
    (options, args) = parser.parse_args()

    if not options.infile:
        print('missing input file (try --help)')
        return 1

    efi_addsig(options.infile, options.outfile, options.addsigs, options.replace)
    return 0

if __name__ == '__main__':
    sys.exit(pe_listsigs())
