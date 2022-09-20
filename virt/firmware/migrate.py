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
                      help = 'use varstore template FILE', metavar = 'FILE',
                      default = '/usr/share/edk2/ovmf/OVMF_VARS.fd')
    parser.add_option('--varstore', dest = 'varstores', type = 'string', action = 'append',
                      help = 'migrate variable store FILE', metavar = 'FILE', default = [])
    parser.add_option('--guest', dest = 'guests', type = 'string', action = 'append',
                      help = 'migrate libvirt guest NAME', metavar = 'NAME', default = [])
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    newstore = edk2.Edk2VarStore(options.template)

    for guest in options.guests:
        options.varstores.append(f'/var/lib/libvirt/qemu/nvram/{guest}_VARS.fd')

    for varsfile in options.varstores:
        oldstore = edk2.Edk2VarStore(varsfile)
        varlist = oldstore.get_varlist()
        newstore.write_varstore(varsfile, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
