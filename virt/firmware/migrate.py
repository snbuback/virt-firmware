#!/usr/bin/python
""" print and edit ovmf varstore files """
import sys
import logging
import optparse

from virt.firmware.varstore import edk2


##################################################################################################
# main

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'info',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_option('--template', dest = 'template', type = 'string',
                      help = 'use varstore template FILE', metavar = 'FILE')
    parser.add_option('--varstore', dest = 'varstore', type = 'string',
                      help = 'migrate variable store FILE', metavar = 'FILE')
    parser.add_option('--guest', dest = 'guest', type = 'string',
                      help = 'migrate libvirt guest NAME', metavar = 'NAME')
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    # check for arguments
    if options.varstore:
        varsfile = options.varstore
    elif options.guest:
        varsfile = f'/var/lib/libvirt/qemu/nvram/{options.guest}_VARS.fd'
    else:
        logging.error('must specify --varstore or --guest')
        sys.exit(1)

    if options.template:
        tmplfile = options.template
    else:
        tmplfile = '/usr/share/edk2/ovmf/OVMF_VARS.fd'

    oldstore = edk2.Edk2VarStore(varsfile)
    newstore = edk2.Edk2VarStore(tmplfile)

    varlist = oldstore.get_varlist()
    newstore.write_varstore(varsfile, varlist)
    return 0

if __name__ == '__main__':
    sys.exit(main())
