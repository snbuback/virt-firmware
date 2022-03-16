#!/usr/bin/python
""" print and edit ovmf varstore files """
import sys
import json
import logging
import optparse

from cryptography import x509

from ovmfctl.efi import guids
from ovmfctl.efi import efijson
from ovmfctl.efi import edk2


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
# main

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
    parser.add_option('--set-json', dest = 'set_json', type = 'string',
                      help = 'set variable from json dump FILE',
                      metavar = 'FILE')
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
    parser.add_option('--write-json', dest = 'write_json', type = 'string',
                      help = 'write json dump to FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    if not options.input:
        logging.error("no input file specified (try -h for help)")
        sys.exit(1)

    edk2store = edk2.Edk2VarStore(options.input)
    varlist = edk2store.get_varlist()

    if options.extract:
        for (key, item) in varlist.items():
            sigdb = item.sigdb
            if sigdb:
                sigdb.extract_certs(key)

    if options.delete:
        for name in options.delete:
            varlist.delete(name)

    if options.set_true:
        for item in options.set_true:
            varlist.set_bool(item, True)

    if options.set_false:
        for item in options.set_false:
            varlist.set_bool(item, False)

    if options.set_json:
        with open(options.set_json, "r", encoding = 'utf-8') as f:
            l = json.loads(f.read(), object_hook = efijson.efi_decode)
        for (key, item) in l.items():
            logging.info('set variable %s from %s', key, options.set_json)
            varlist[key] = item

    if options.redhat:
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()

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
        varlist.enable_secureboot()

    if options.print:
        print_vars(varlist, options.verbose, options.hexdump)

    if options.output:
        edk2store.write_varstore(options.output, varlist)

    if options.write_json:
        j = json.dumps(varlist, cls=efijson.EfiJSONEncoder, indent = 4)
        with open(options.write_json, "w", encoding = 'utf-8') as f:
            f.write(j)

    return 0

if __name__ == '__main__':
    sys.exit(main())
