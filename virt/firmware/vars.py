#!/usr/bin/python
""" print and edit ovmf varstore files """
import sys
import json
import logging
import optparse

from virt.firmware.efi import efivar
from virt.firmware.efi import efijson
from virt.firmware.efi import devpath
from virt.firmware.efi import ucs16

from virt.firmware.varstore import edk2
from virt.firmware.varstore import aws


##################################################################################################
# main

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'info',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'read edk2 or aws vars from FILE', metavar = 'FILE')
    parser.add_option('--extract-certs', dest = 'extract',
                      action = 'store_true', default = False,
                      help = 'extract all certificates')

    pgroup = optparse.OptionGroup(parser, 'Variable options')
    pgroup.add_option('-d', '--delete', dest = 'delete',
                      action = 'append', type = 'string',
                      help = 'delete variable VAR, can be specified multiple times',
                      metavar = 'VAR')
    pgroup.add_option('--set-true', dest = 'set_true',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to true, can be specified multiple times',
                      metavar = 'VAR')
    pgroup.add_option('--set-false', dest = 'set_false',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to false, can be specified multiple times',
                      metavar = 'VAR')
    pgroup.add_option('--set-json', dest = 'set_json', type = 'string',
                      help = 'set variables from json dump FILE',
                      metavar = 'FILE')
    parser.add_option_group(pgroup)

    pgroup = optparse.OptionGroup(parser, 'Boot configuration')
    pgroup.add_option('--set-boot-uri', dest = 'set_boot_uri',
                      help = 'set network boot uri to LINK (once, using BootNext)',
                      metavar = 'LINK')
    pgroup.add_option('--append-boot-filepath', dest = 'append_boot_filepath',
                      action = 'append', type = 'string',
                      help = 'append boot entry for FILE (permanent, using BootOrder)',
                      metavar = 'FILE')
    parser.add_option_group(pgroup)

    pgroup = optparse.OptionGroup(parser, 'Secure boot setup options')
    pgroup.add_option('--set-pk', dest = 'pk',  nargs = 2,
                      help = 'set PK to x509 cert, loaded in pem format ' +
                      'from FILE and with owner GUID',
                      metavar = ('GUID', 'FILE'))
    pgroup.add_option('--add-kek', dest = 'kek',  action = 'append', nargs = 2,
                      help = 'add x509 cert to KEK, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    pgroup.add_option('--add-db', dest = 'db',  action = 'append', nargs = 2,
                      help = 'add x509 cert to db, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    pgroup.add_option('--add-mok', dest = 'mok',  action = 'append', nargs = 2,
                      help = 'add x509 cert to MokList, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    pgroup.add_option('--add-db-hash', dest = 'db_hash',  action = 'append', nargs = 2,
                      help = 'add sha256 HASH to db, with owner GUID, ' +
                      'can be specified multiple times',
                      metavar = ('GUID', 'HASH'))
    pgroup.add_option('--add-mok-hash', dest = 'mok_hash',  action = 'append', nargs = 2,
                      help = 'add sha256 HASH to MokList, with owner GUID, ' +
                      'can be specified multiple times',
                      metavar = ('GUID', 'HASH'))
    parser.add_option_group(pgroup)

    pgroup = optparse.OptionGroup(parser, 'Secure boot convinience shortcuts')
    pgroup.add_option('--enroll-redhat', dest = 'redhat',
                      action = 'store_true', default = False,
                      help = 'enroll default certificates for redhat platform')
    pgroup.add_option('--no-microsoft', dest = 'microsoft',
                      action = 'store_false', default = True,
                      help = 'do not add microsoft keys')
    pgroup.add_option('--distro-keys', dest = 'distro', type = 'string', action = 'append',
                      help = 'add ca keys for DISTRO', metavar = 'DISTRO')
    pgroup.add_option('--sb', '--secure-boot', dest = 'secureboot',
                      action = 'store_true', default = False,
                      help = 'enable secure boot mode')
    parser.add_option_group(pgroup)

    pgroup = optparse.OptionGroup(parser, 'Print options')
    pgroup.add_option('-p', '--print', dest = 'print',
                      action = 'store_true', default = False,
                      help = 'print varstore')
    pgroup.add_option('-v', '--verbose', dest = 'verbose',
                      action = 'store_true', default = False,
                      help = 'print varstore verbosely')
    pgroup.add_option('-x', '--hexdump', dest = 'hexdump',
                      action = 'store_true', default = False,
                      help = 'print variable hexdumps')
    parser.add_option_group(pgroup)

    pgroup = optparse.OptionGroup(parser, 'Output options')
    pgroup.add_option('-o', '--output', dest = 'output', type = 'string',
                      help = 'write edk2 or aws vars to FILE, using the same format '
                      'the --input FILE has.', metavar = 'FILE')
    pgroup.add_option('--output-aws', dest = 'output_aws', type = 'string',
                      help = 'write aws vars to FILE', metavar = 'FILE')
    pgroup.add_option('--output-json', dest = 'output_json', type = 'string',
                      help = 'write json dump to FILE', metavar = 'FILE')
    parser.add_option_group(pgroup)
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    edk2store = None
    awsstore = None
    varlist = efivar.EfiVarList()

    if options.input:
        if edk2.Edk2VarStore.probe(options.input):
            edk2store = edk2.Edk2VarStore(options.input)
            varlist = edk2store.get_varlist()
        elif aws.AwsVarStore.probe(options.input):
            awsstore = aws.AwsVarStore(options.input)
            varlist = awsstore.get_varlist()
        else:
            logging.error("unknown input file format")
            sys.exit(1)

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

    if options.set_boot_uri:
        items = options.set_boot_uri.split('/')
        title = 'netboot ' + items[-1]
        bpath = devpath.DevicePath.uri(options.set_boot_uri)
        varlist.set_boot_entry(0x99, title, bpath)
        varlist.set_boot_next(0x99)

    if options.append_boot_filepath:
        for item in options.append_boot_filepath:
            strings = item.replace('/', '\\').split(' ')
            filepath = strings[0]
            if len(strings) > 1:
                optdata = bytes(ucs16.from_string(strings[1]))
            else:
                optdata = None
            items = filepath.split('\\')
            title = 'file ' + items[-1]
            bpath = devpath.DevicePath.filepath(filepath)
            index = varlist.add_boot_entry(title, bpath, optdata)
            varlist.append_boot_order(index)

    if options.set_json:
        with open(options.set_json, "r", encoding = 'utf-8') as f:
            l = json.loads(f.read(), object_hook = efijson.efi_decode)
        for (key, item) in l.items():
            logging.info('set variable %s from %s', key, options.set_json)
            varlist[key] = item

    if options.redhat:
        varlist.enroll_platform_redhat()
        if options.microsoft:
            varlist.add_microsoft_keys()

    if options.distro:
        for item in options.distro:
            varlist.add_distro_keys(item)

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

    if options.db_hash:
        for item in options.db_hash:
            varlist.add_hash('db', item[0], item[1])

    if options.mok_hash:
        for item in options.mok_hash:
            varlist.add_hash('MokList', item[0], item[1])

    if options.secureboot:
        varlist.enable_secureboot()

    if options.print:
        if options.verbose:
            varlist.print_normal(options.hexdump)
        else:
            varlist.print_compact()

    if options.output:
        if edk2store:
            edk2store.write_varstore(options.output, varlist)
        elif awsstore:
            awsstore.write_varstore(options.output, varlist)
        else:
            logging.error("no input file specified (needed as edk2 varstore template)")
            sys.exit(1)

    if options.output_aws:
        if options.output_aws == "-":
            print(aws.AwsVarStore.base64_varstore(varlist).decode())
        else:
            aws.AwsVarStore.write_varstore(options.output_aws, varlist)

    if options.output_json:
        j = json.dumps(varlist, cls=efijson.EfiJSONEncoder, indent = 4)
        if options.output_json == "-":
            print(j)
        else:
            logging.info('writing json varstore to %s', options.output_json)
            with open(options.output_json, "w", encoding = 'utf-8') as f:
                f.write(j)

    return 0

if __name__ == '__main__':
    sys.exit(main())
