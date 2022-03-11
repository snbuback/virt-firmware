#!/usr/bin/python
""" print and edit ovmf varstore files """
import sys
import json
import struct
import logging
import optparse
import pkg_resources

from cryptography import x509

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16
from ovmfctl.efi import efivar
from ovmfctl.efi import efijson


##################################################################################################
# parse stuff

def parse_vars(data, start, end):
    pos = start
    varlist = efivar.EfiVarList()
    while pos < end:
        (magic, state, attr, count) = struct.unpack_from("=HBxLQ", data, pos)
        if magic != 0x55aa:
            break
        (pk, nsize, dsize) = struct.unpack_from("=LLL", data, pos + 32)

        if state == 0x3f:
            var = efivar.EfiVar(ucs16.from_ucs16(data, pos + 44 + 16),
                                guid = guids.parse_bin(data, pos + 44),
                                attr = attr,
                                data = data[pos + 44 + 16 + nsize :
                                            pos + 44 + 16 + nsize + dsize],
                                count = count,
                                pkidx = pk)
            var.parse_time(data, pos + 16)
            varlist[str(var.name)] = var

        pos = pos + 44 + 16 + nsize + dsize
        pos = (pos + 3) & ~3 # align
    return varlist

def parse_varstore(file, data, start):
    guid = guids.parse_bin(data, start)
    (size, storefmt, state) = struct.unpack_from("=LBB", data, start + 16)
    logging.debug('varstore=%s size=0x%x format=0x%x state=0x%x',
                  guids.name(guid), size, storefmt, state)
    if str(guid) != guids.AuthVars:
        logging.error('%s: unknown varstore guid', file)
        sys.exit(1)
    if storefmt != 0x5a:
        logging.error('%s: unknown varstore format', file)
        sys.exit(1)
    if state != 0xfe:
        logging.error('%s: unknown varstore state', file)
        sys.exit(1)
    return (start + 16 + 12, start + size)

def parse_volume(file, data):
    guid = guids.parse_bin(data, 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
        struct.unpack_from("=QLLHHHxBLL", data, 32)
    logging.debug('vol=%s vlen=0x%x rev=%d blocks=%d*%d (0x%x)',
                  guids.name(guid), vlen, rev,
                  blocks, blksize, blocks * blksize)
    if sig != 0x4856465f:
        logging.error('%s: not a firmware volume', file)
        sys.exit(1)
    if str(guid) != guids.NvData:
        logging.error('%s: not a variable store', file)
        sys.exit(1)
    return parse_varstore(file, data, hlen)


##################################################################################################
# print stuff, debug logging

def print_hexdump(data, start, end):
    hstr = ''
    astr = ''
    pos = start
    count = 0
    while True:
        hstr += f'{data[start+count]:02x} '
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            astr += f'{data[start+count]:c}'
        else:
            astr += '.'
        count += 1
        if count % 4 == 0:
            hstr += ' '
            astr += ' '
        if count % 16 == 0 or start+count == end:
            print(f'    {pos:06x}:  {hstr:52s} {astr}')
            hstr = ''
            astr = ''
            pos += 16
        if count == 256 or start+count == end:
            break
    if start+count < end:
        print(f'    {pos:06x}: [ ... ]')

def print_sigdb(var):
    for item in var.sigdb:
        name = guids.name(item.guid)
        count = len(item)
        print(f'    list type={name} count={count}')
        if item.x509:
            cn = item.x509.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
            print(f'      x509 CN={cn.value}')

def print_var(var, verbose, hexdump):
    name = str(var.name)
    gname = guids.name(var.guid)
    size = len(var.data)
    print(f'  - name={name} guid={gname} size={size}')
    desc = var.fmt_data()
    if desc:
        print(f'    {desc}')
    if var.sigdb:
        print_sigdb(var)
    if verbose:
        print("----- raw -----")
        print(json.dumps(var, cls=efijson.EfiJSONEncoder, indent = 4))
        print("----- end -----")
    if hexdump:
        print_hexdump(var.data, 0, len(var.data))

def print_vars(varlist, verbose, hexdump):
    logging.info("printing variables ...")
    for (key, item) in varlist.items():
        print_var(item, verbose, hexdump)


##################################################################################################
# write vars

def write_var(var):
    blob = struct.pack("=HBxLQ",
                       0x55aa, 0x3f,
                       var.attr,
                       var.count)
    blob += var.bytes_time()
    blob += struct.pack("=LLL",
                        var.pkidx,
                        var.name.size(),
                        len(var.data))
    blob += var.guid.bytes_le
    blob += bytes(var.name)
    blob += var.data
    while len(blob) & 3:
        blob += b'\0'
    return blob

##################################################################################################
# main

def enable_secureboot(varlist):
    varlist.add_dummy_dbx(guids.OvmfEnrollDefaultKeys)
    varlist.set_bool('SecureBootEnable', True)
    varlist.set_bool('CustomMode', False)

def platform_redhat(varlist):
    redhat_pk = pkg_resources.resource_filename('ovmfctl',
                                                'certs/RedHatSecureBootPKKEKkey1.pem')
    varlist.add_cert('PK', guids.OvmfEnrollDefaultKeys, redhat_pk, True)
    varlist.add_cert('KEK', guids.OvmfEnrollDefaultKeys, redhat_pk, True)
    varlist.add_dummy_dbx(guids.OvmfEnrollDefaultKeys)

def microsoft_keys(varlist):
    ms_kek = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftCorporationKEKCA2011.pem')
    ms_win = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftWindowsProductionPCA2011.pem')
    ms_3rd = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftCorporationUEFICA2011.pem')
    varlist.add_cert('KEK', guids.MicrosoftVendor, ms_kek, False)
    varlist.add_cert('db', guids.MicrosoftVendor, ms_win, False) # windows
    varlist.add_cert('db', guids.MicrosoftVendor, ms_3rd, False) # 3rd party (shim.efi)

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'info',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_option('--extract-certs', dest = 'extract',
                      action = 'store_true', default = False,
                      help = 'extract all certificates')
    parser.add_option('-d', '--delete', dest = 'delete',
                      action = 'append', type = 'string',
                      help = 'delete variable VAR, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-true', dest = 'set_true',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to true, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-false', dest = 'set_false',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to false, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-pk', dest = 'pk',  nargs = 2,
                      help = 'set PK to x509 cert, loaded in pem format ' +
                      'from FILE and with owner GUID',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-kek', dest = 'kek',  action = 'append', nargs = 2,
                      help = 'add x509 cert to KEK, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-db', dest = 'db',  action = 'append', nargs = 2,
                      help = 'add x509 cert to db, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-mok', dest = 'mok',  action = 'append', nargs = 2,
                      help = 'add x509 cert to MokList, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--enroll-redhat', dest = 'redhat',
                      action = 'store_true', default = False,
                      help = 'enroll default certificates for redhat platform')
    parser.add_option('--sb', '--secure-boot', dest = 'secureboot',
                      action = 'store_true', default = False,
                      help = 'enable secure boot mode')
    parser.add_option('-p', '--print', dest = 'print',
                      action = 'store_true', default = False,
                      help = 'print varstore')
    parser.add_option('-v', '--verbose', dest = 'verbose',
                      action = 'store_true', default = False,
                      help = 'print varstore verbosely')
    parser.add_option('-x', '--hexdump', dest = 'hexdump',
                      action = 'store_true', default = False,
                      help = 'print variable hexdumps')
    parser.add_option('-o', '--output', dest = 'output', type = 'string',
                      help = 'write edk2 vars to FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    if not options.input:
        logging.error("no input file specified (try -h for help)")
        sys.exit(1)

    logging.info('reading varstore from %s', options.input)
    with open(options.input, "rb") as f:
        infile = f.read()

    (start, end) = parse_volume(options.input, infile)
    logging.info('var store range: 0x%x -> 0x%x', start, end)
    varlist = parse_vars(infile, start, end)

    if options.extract:
        for (key, item) in varlist.items():
            sigdb = item.sigdb
            if sigdb:
                sigdb.extract_certs(key)

    if options.delete:
        varlist.delete(options.delete)

    if options.set_true:
        for item in options.set_true:
            varlist.set_bool(item, True)

    if options.set_false:
        for item in options.set_false:
            varlist.set_bool(item, False)

    if options.redhat:
        platform_redhat(varlist)
        microsoft_keys(varlist)

    if options.pk:
        varlist.add_cert('PK', options.pk[0], options.pk[1], True)

    if options.kek:
        for item in options.kek:
            varlist.add_cert('KEK', item[0], item[1])

    if options.db:
        for item in options.db:
            varlist.add_cert('db', item[0], item[1])

    if options.mok:
        for item in options.mok:
            varlist.add_cert('MokList', item[0], item[1])

    if options.secureboot:
        enable_secureboot(varlist)

    if options.print:
        print_vars(varlist, options.verbose, options.hexdump)

    if options.output:
        outfile = infile[:start]
        for (key, item) in varlist.items():
            outfile += write_var(item)

        if len(outfile) > end:
            logging.error("varstore is too small")
            sys.exit(1)

        outfile += b''.zfill(end - len(outfile))
        outfile += infile[end:]

        logging.info('writing varstore to %s', options.output)
        with open(options.output, "wb") as f:
            f.write(outfile)

    return 0

if __name__ == '__main__':
    sys.exit(main())
