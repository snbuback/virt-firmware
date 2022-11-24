#!/usr/bin/python
""" handle dbx updates -- EXPERIMENTAL """
import sys
import logging
import optparse

from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar
from virt.firmware.varstore import edk2

def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'info',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_option('-u', '--update', dest = 'update', type = 'string',
                      help = 'read dbx update from FILE', metavar = 'FILE')
    parser.add_option('-p', '--print', dest = 'print', action = 'store_true', default = False,
                      help = 'print dbx update content')
    parser.add_option('--vars', '--varstore', dest = 'varstore', type = 'string',
                      help = 'update edk2 varstore FILE inplace', metavar = 'FILE')
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    if not options.update:
        logging.error('missing dbx update file (try --help)')
        return 1

    logging.info('reading dbx update from %s', options.update)
    with open(options.update, 'rb') as f:
        blob = f.read()
    dbx = efivar.EfiVar(ucs16.from_string('dbx'), authdata = blob)

    if options.print:
        for slist in dbx.sigdb:
            efivar.EfiVarList.print_siglist(slist)

    if options.varstore:
        edk2store = edk2.Edk2VarStore(options.varstore)
        varlist = edk2store.get_varlist()
        logging.info('setting variable dbx')
        varlist['dbx'] = dbx
        edk2store.write_varstore(options.varstore, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
