#/usr/bin/python3
import sys
import struct
import logging
import argparse

from virt.firmware.efi import guids
from virt.firmware.efi import bootentry

from virt.firmware.varstore import linux


class EfiBootConfig:

    def __init__(self):
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

    def print_entry(self, nr):
        entry = self.bentr[nr]
        cstr = 'C' if nr == self.bcurr else ' '
        nstr = 'N' if nr == self.bnext else ' '
        ostr = 'O' if nr in self.blist else ' '
        print(f'# {cstr} {nstr} {ostr}  -  {nr:04x}  -  {entry.title}')
        
    def print_cfg(self):
        print('# C - BootCurrent, N - BootNext, O - BootOrder')
        print('# --------------------------------------------')
        if self.bcurr and not self.bcurr in self.blist:
            self.print_entry(self.bcurr)
        if self.bnext and not self.bnext in self.blist and self.bcurr != self.bnext:
            self.print_entry(self.bnext)
        for nr in self.blist:
            self.print_entry(nr)


class LinuxEfiBootConfig(EfiBootConfig):

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
            var = self.linux_read_variable(f'Boot{nr:04x}')
            self.bentr[nr] = bootentry.BootEntry(data = var.data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    bootcfg = LinuxEfiBootConfig()
    bootcfg.print_cfg()


if __name__ == '__main__':
    sys.exit(main())
