#!/usr/bin/python
""" print and edit efi sigdb files """
import sys
import optparse

from virt.firmware.efi import guids
from virt.firmware.efi import efivar
from virt.firmware.efi import siglist

def main():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'read efi sigdb FILE', metavar = 'FILE')
    parser.add_option('-o', '--output', dest = 'output', type = 'string',
                      help = 'write efi sigdb FILE.', metavar = 'FILE')
    parser.add_option('--add-cert', dest = 'certs',  action = 'append', nargs = 2,
                      help = 'add x509 cert to sigdb, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('-p', '--print', dest = 'print',
                      action = 'store_true', default = False,
                      help = 'print sigdb')
    (options, args) = parser.parse_args()

    if options.input:
        with open(options.input, "rb") as f:
            sigdb = siglist.EfiSigDB(f.read())
    else:
        sigdb = siglist.EfiSigDB()

    if options.certs:
        for item in options.certs:
            sigdb.add_cert(guids.parse_str(item[0]), item[1])

    if options.print and sigdb:
        for slist in sigdb:
            efivar.EfiVarList.print_siglist(slist)

    if options.output:
        with open(options.output, "wb") as f:
            f.write(bytes(sigdb))

if __name__ == '__main__':
    sys.exit(main())
