#/usr/bin/python3
# pylint: disable=consider-iterating-dictionary
""" experimental efi boot config tool """
import sys
import struct
import logging
import argparse

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import bootentry

from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2
from virt.firmware.varstore import linux


class EfiBootConfig:
    """ efi boot configuration """

    def __init__(self):
        self.bootorder   = None
        self.bootcurrent = None
        self.bootnext    = None
        self.bcurr = None  # parsed BootCurrent
        self.bnext = None  # parsed BootNext
        self.blist = []    # parsed BootOrder
        self.bentr = {}    # parsed BootNNNN entries

    def parse_boot_variables(self):
        if self.bootorder:
            self.blist = []
            for pos in range(len(self.bootorder.data) >> 1):
                nr = struct.unpack_from('=H', self.bootorder.data, pos * 2)
                self.blist.append(nr[0])
                self.bentr[nr[0]] = None
        if self.bootcurrent:
            nr = struct.unpack_from('=H', self.bootcurrent.data)
            self.bcurr = nr[0]
            self.bentr[nr[0]] = None
        if self.bootnext:
            nr = struct.unpack_from('=H', self.bootcurrent.data)
            self.bnext = nr[0]
            self.bentr[nr[0]] = None

    def print_entry(self, nr, verbose):
        entry = self.bentr[nr]
        cstr = 'C' if nr == self.bcurr else ' '
        nstr = 'N' if nr == self.bnext else ' '
        ostr = 'O' if nr in self.blist else ' '
        if not entry:
            print(f'# {cstr} {nstr} {ostr}  -  {nr:04x}  -  [ missing ]')
            return
        print(f'# {cstr} {nstr} {ostr}  -  {nr:04x}  -  {entry.title}')
        if verbose:
            prefix = '#                    ->'
            print(f'{prefix} devpath: {entry.devicepath}')
            if entry.optdata:
                if len(entry.optdata) >= 4 and entry.optdata[0] != 0 and entry.optdata[1] == 0:
                    print(f'{prefix} optdata/ucs16: {ucs16.from_ucs16(entry.optdata, 0)}')
                else:
                    print(f'{prefix} optdata/hex: {entry.optdata.hex()}')

    def print_cfg(self, verbose = False):
        print('# C - BootCurrent, N - BootNext, O - BootOrder')
        print('# --------------------------------------------')
        if self.bcurr and not self.bcurr in self.blist:
            self.print_entry(self.bcurr, verbose)
        if self.bnext and not self.bnext in self.blist and self.bcurr != self.bnext:
            self.print_entry(self.bnext, verbose)
        for nr in self.blist:
            self.print_entry(nr, verbose)


class LinuxEfiBootConfig(EfiBootConfig):
    """ read efi boot configuration from linux sysfs """

    def __init__(self):
        super().__init__()
        self.linux_init()

    @staticmethod
    def linux_read_variable(name):
        return linux.LinuxVarStore.get_variable(name, guids.EfiGlobalVariable)

    def linux_init(self):
        self.bootorder = self.linux_read_variable('BootOrder')
        self.bootcurrent = self.linux_read_variable('BootCurrent')
        self.bootnext = self.linux_read_variable('BootNext')
        self.parse_boot_variables()
        for nr in self.bentr.keys():
            var = self.linux_read_variable(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)


class VarStoreEfiBootConfig(EfiBootConfig):
    """ read efi boot configuration from varstore  """

    def __init__(self, filename):
        super().__init__()
        self.varstore = None
        self.varlist  = None
        self.varstore_init(filename)

    def varstore_init(self, filename):
        if edk2.Edk2VarStore.probe(filename):
            self.varstore = edk2.Edk2VarStore(filename)
        elif edk2.Edk2VarStoreQcow2.probe(filename):
            self.varstore = edk2.Edk2VarStoreQcow2(filename)
        elif aws.AwsVarStore.probe(filename):
            self.varstore = aws.AwsVarStore(filename)
        else:
            return

        self.varlist = self.varstore.get_varlist()
        self.bootcurrent = None
        self.bootorder = self.varlist.get('BootOrder')
        self.bootnext = self.varlist.get('BootNext')
        self.parse_boot_variables()
        for nr in self.bentr.keys():
            var = self.varlist.get(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--vars', dest = 'varsfile', type = str,
                        help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more details')
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    if options.varsfile:
        bootcfg = VarStoreEfiBootConfig(options.varsfile)
    else:
        bootcfg = LinuxEfiBootConfig()

    bootcfg.print_cfg(options.verbose)
    return 0

if __name__ == '__main__':
    sys.exit(main())
