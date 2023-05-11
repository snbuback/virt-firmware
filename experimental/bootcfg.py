#/usr/bin/python3
# pylint: disable=consider-iterating-dictionary,too-many-instance-attributes
""" experimental efi boot config tool """
import re
import sys
import struct
import logging
import argparse
import subprocess

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar
from virt.firmware.efi import devpath
from virt.firmware.efi import bootentry

from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2
from virt.firmware.varstore import linux


########################################################################
# EfiBootConfig class + children

class EfiBootConfig:
    """ efi boot configuration """

    def __init__(self):
        self.bootorder   = None
        self.bootcurrent = None
        self.bootnext    = None
        self.bcurr = None  # parsed BootCurrent
        self.bnext = None  # parsed BootNext
        self.blist = []    # parsed BootOrder
        self.unused = []   # unused BootNNNN entry list
        self.bentr = {}    # parsed BootNNNN entries
        self.bnext_updated = False
        self.blist_updated = False

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
            nr = struct.unpack_from('=H', self.bootnext.data)
            self.bnext = nr[0]
            self.bentr[nr[0]] = None

    def add_unused_entries(self, names):
        regex = re.compile('Boot([0-9A-Z]{4})')
        for name in names:
            result = regex.match(name)
            if not result:
                continue
            nr = int(result.group(1), 16)
            if nr in self.bentr:
                continue
            self.unused.append(nr)
            self.bentr[nr] = None

    @staticmethod
    def print_optdata(prefix, optdata):
        if len(optdata) >= 4 and optdata[0] != 0 and optdata[1] == 0:
            print(f'{prefix} opt/ucs16: {ucs16.from_ucs16(optdata, 0)}')
        elif len(optdata) == 16:
            print(f'{prefix} opt/guid: {guids.parse_bin(optdata, 0)}')
        else:
            print(f'{prefix} opt/hex: {optdata.hex()}')

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
            print(f'{prefix} path: {entry.devicepath}')
            if entry.optdata:
                self.print_optdata(prefix, entry.optdata)
            print('#')

    def print_cfg(self, verbose = False):
        print('# C - BootCurrent, N - BootNext, O - BootOrder')
        print('# --------------------------------------------')
        if self.bcurr is not None and not self.bcurr in self.blist:
            self.print_entry(self.bcurr, verbose)
        if self.bnext is not None and not self.bnext in self.blist and self.bcurr != self.bnext:
            self.print_entry(self.bnext, verbose)
        for nr in self.blist:
            self.print_entry(nr, verbose)
        for nr in self.unused:
            self.print_entry(nr, verbose)

    def find_uki_entry(self, uki):
        for (nr, entry) in self.bentr.items():
            if not entry.optdata:
                continue
            optpath = str(ucs16.from_ucs16(entry.optdata, 0))
            if optpath == str(uki):
                return nr
        return None

    def find_unused_entry(self):
        nr = 0
        while nr in self.bentr:
            nr += 1
        return nr

    def add_entry(self, entry):
        nr = self.find_unused_entry()
        self.bentr[nr] = entry
        self.unused.append(nr)
        return nr

    def remove_entry(self, nr):
        del self.bentr[nr]
        if nr == self.bnext:
            self.bnext = None
            self.bnext_updated = True
        if nr in self.blist:
            self.blist = filter(lambda x: x != nr, self.blist)
            self.blist_updated = True
        if nr in self.unused:
            self.unused = filter(lambda x: x != nr, self.unused)

    def set_boot_next(self, nr):
        self.bnext = nr
        self.bnext_updated = True

    def set_boot_order(self, nr, pos):
        self.blist = filter(lambda x: x != nr, self.blist)
        self.blist.insert(pos, nr)
        self.blist_updated = True


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
        self.add_unused_entries(self.varlist.keys())
        for nr in self.bentr.keys():
            var = self.varlist.get(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)


class LinuxEfiBootConfig(EfiBootConfig):
    """ read efi boot configuration from linux sysfs """

    def __init__(self):
        super().__init__()
        self.varstore = None
        self.linux_init()

    def linux_read_variable(self, name):
        return self.varstore.get_variable(name, guids.EfiGlobalVariable)

    def linux_wite_variable(self, var):
        self.varstore.set_variable(var)

    def linux_write_entry(self, nr):
        var = efivar.EfiVar(ucs16.from_string(f'Boot{nr:04X}'),
                            guid = guids.parse_str(guids.EfiGlobalVariable),
                            data = bytes(self.bentr[nr]))
        self.varstore.set_variable(var)

    def linux_remove_entry(self, nr):
        name = f'Boot{nr:04X}'
        self.varstore.del_variable(name, guids.EfiGlobalVariable)

    def linux_update_next(self):
        if not self.bnext_updated:
            return
        if self.bnext is None:
            self.varstore.del_variable('BootNext', guids.EfiGlobalVariable)
            return
        var = efivar.EfiVar(ucs16.from_string('BootNext'),
                            guid = guids.parse_str(guids.EfiGlobalVariable))
        var.set_boot_next(self.bnext)
        self.varstore.set_variable(var)

    def linux_update_order(self):
        if not self.blist_updated:
            return
        var = efivar.EfiVar(ucs16.from_string('BootOrder'),
                            guid = guids.parse_str(guids.EfiGlobalVariable))
        var.set_boot_order(self.blist)
        self.varstore.set_variable(var)

    def linux_init(self):
        self.varstore = linux.LinuxVarStore()
        self.bootorder = self.linux_read_variable('BootOrder')
        self.bootcurrent = self.linux_read_variable('BootCurrent')
        self.bootnext = self.linux_read_variable('BootNext')
        self.parse_boot_variables()
        self.add_unused_entries(self.varstore.scan[guids.EfiGlobalVariable])
        for nr in self.bentr.keys():
            var = self.linux_read_variable(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)


########################################################################
# LinuxBlockDev class

class LinuxBlockDev:
    """ block device """

    def __init__(self, mount, device = None):
        self.mount = mount
        self.device = device
        self.udevenv = {}
        if not self.device:
            self.find_device(mount)
        if self.device:
            self.device_info()

    def find_device(self, mount):
        result = subprocess.run([ 'mount', ], stdout = subprocess.PIPE, check = True)
        for line in result.stdout.decode().split('\n'):
            try:
                (dev, o, mnt, t, fs, opts) = line.split(' ')
            except ValueError:
                continue
            if mnt != mount:
                continue
            self.device = dev
            return
        return

    def device_info(self):
        result = subprocess.run([ 'udevadm', 'info', self.device ],
                                stdout = subprocess.PIPE, check = True)
        regex = re.compile('^E: ([A-Z0-9_]+)=([^\n]*)')
        for line in result.stdout.decode().split('\n'):
            m = regex.match(line)
            if not m:
                continue
            self.udevenv[m.group(1)] = m.group(2)

    def efi_filename(self, filename):
        if not filename.startswith(self.mount):
            logging.error('%s is not on %s', filename, self.mount)
            sys.exit(1)
        return filename[ len(self.mount) : ].replace('/', '\\')

    def dev_path_elem_file(self, filename):
        elem = devpath.DevicePathElem()
        elem.set_filepath(self.efi_filename(filename))
        return elem

    def dev_path_elem_gpt(self):
        elem = devpath.DevicePathElem()
        if self.udevenv['ID_PART_ENTRY_SCHEME'] != 'gpt':
            logging.error('partition table is not gpt')
            sys.exit(1)
        elem.set_gpt(int(self.udevenv['ID_PART_ENTRY_NUMBER']),
                     int(self.udevenv['ID_PART_ENTRY_OFFSET']),
                     int(self.udevenv['ID_PART_ENTRY_SIZE']),
                     self.udevenv['ID_PART_ENTRY_UUID'])
        return elem

    def dev_path_file(self, filename):
        path = devpath.DevicePath()
        path.append(self.dev_path_elem_gpt())
        path.append(self.dev_path_elem_file(filename))
        return path


########################################################################
# main

def esp_path():
    result = subprocess.run([ 'bootctl', '--print-esp-path' ],
                            stdout = subprocess.PIPE, check = True)
    return result.stdout.decode().strip('\n')

def add_uki(bootcfg, esp, options):
    if not options.shim:
        logging.error('shim binary not specified')
        sys.exit(1)
    if not options.title:
        logging.error('entry title not specified')
        sys.exit(1)

    efiuki  = esp.efi_filename(options.adduki)
    nr = bootcfg.find_uki_entry(efiuki)
    if nr is not None:
        logging.info('Entry exists (Boot%04X)', nr)
    else:
        devicepath = esp.dev_path_file(options.shim)
        optdata = ucs16.from_string(efiuki)
        entry = bootentry.BootEntry(title = ucs16.from_string(options.title),
                                    attr = bootentry.LOAD_OPTION_ACTIVE,
                                    devicepath = devicepath,
                                    optdata = bytes(optdata))
        logging.info('Create new entry: %s', str(entry))
        nr = bootcfg.add_entry(entry)
        logging.info('Added entry (Boot%04X)', nr)
        if not options.dryrun:
            bootcfg.linux_write_entry(nr)

    if options.bootnext:
        bootcfg.set_boot_next(nr)
        if not options.dryrun:
            bootcfg.linux_update_next()


def remove_uki(bootcfg, esp, options):
    efiuki = esp.efi_filename(options.removeuki)
    nr = bootcfg.find_uki_entry(efiuki)
    if nr is None:
        logging.warning('No entry found for %s', options.removeuki)
        return

    logging.info('Removing entry (Boot%04X)', nr)
    bootcfg.remove_entry(nr)
    if not options.dryrun:
        bootcfg.linux_remove_entry(nr)
        bootcfg.linux_update_next()
        bootcfg.linux_update_order()


def boot_success(bootcfg):
    if bootcfg.bcurr == bootcfg.blist[0]:
        logging.info('No update needed, BootCurrent already comes first in BootOrder.')
        return
    logging.info('Add BootCurrent (Boot%04X) to BootOrder', bootcfg.bcurr)
    bootcfg.set_boot_order(bootcfg.bcurr, 0)
    if not options.dryrun:
        bootcfg.linux_update_order()

def main():
    parser = argparse.ArgumentParser(
        description = 'show and manage uefi boot entries')

    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--vars', dest = 'varsfile', type = str,
                        help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_argument('--show', dest = 'show',
                        action = 'store_true', default = False,
                        help = 'print boot configuration')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more details')

    group = parser.add_argument_group('update unified kernel image (UKI) boot entries')
    group.add_argument('--add-uki', dest = 'adduki', type = str,
                       help = 'add boot entry for UKI image FILE', metavar = 'FILE')
    group.add_argument('--remove-uki', dest = 'removeuki', type = str,
                       help = 'remove boot entry for UKI image FILE', metavar = 'FILE')
    group.add_argument('--boot-success', dest = 'bootok',
                       action = 'store_true', default = False,
                       help = 'boot is successful, update BootOrder')

    group = parser.add_argument_group('options for UKI updates')
    group.add_argument('--dry-run', dest = 'dryrun',
                       action = 'store_true', default = False,
                       help = 'do not actually update the configuration')
    group.add_argument('--title', dest = 'title', type = str,
                       help = 'label the entry with TITLE', metavar = 'TITLE')
    group.add_argument('--shim', dest = 'shim', type = str,
                       help = 'use shim binary FILE', metavar = 'FILE')
    group.add_argument('--once', '--boot-next', dest = 'bootnext',
                       action = 'store_true', default = False,
                       help = 'boot added entry once (using BootNext)')

    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    # sanity checks
    if options.varsfile and (options.adduki or
                             options.removeuki):
        logging.error('operation not supported for edk2 varstores')
        sys.exit(1)

    # read info
    if options.varsfile:
        bootcfg = VarStoreEfiBootConfig(options.varsfile)
    else:
        esp = LinuxBlockDev(esp_path())
        bootcfg = LinuxEfiBootConfig()
        #print(esp.dev_path_file('/boot/efi/EFI/fedora/shimx64.efi'))

    # apply updates
    if options.adduki:
        add_uki(bootcfg, esp, options)
    elif options.removeuki:
        remove_uki(bootcfg, esp, options)
    elif options.bootok:
        boot_success(bootcfg)
    else:
        # default action
        options.show = True

    # print info
    if options.show:
        bootcfg.print_cfg(options.verbose)

    return 0

if __name__ == '__main__':
    sys.exit(main())
