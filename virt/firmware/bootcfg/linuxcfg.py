#/usr/bin/python3
# pylint: disable=consider-iterating-dictionary
""" linux specific boot config management code """
import os
import re
import sys
import logging
import subprocess
import collections

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar
from virt.firmware.efi import devpath
from virt.firmware.efi import bootentry

from virt.firmware.varstore import linux

from virt.firmware.bootcfg import bootcfg

class LinuxEfiBootConfig(bootcfg.EfiBootConfig):
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


class LinuxBlockDev:
    """ linux block device and file system, functions to translate
    linux file paths to efi paths (aka strings) and efi device paths
    (aka EFI_DEVICE_PATH_PROTOCOLs) """

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
        with os.scandir(mount) as unused:
            # nothing to to, just trigger automount
            pass
        for line in result.stdout.decode().split('\n'):
            try:
                (dev, o, mnt, t, fs, opts) = line.split(' ')
            except ValueError:
                continue
            if fs == 'autofs':
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


class LinuxOsInfo(collections.UserDict):
    """ parser for /etc/os-release """

    def __init__(self, path = None):
        super().__init__()
        self.blob = None
        if path:
            with open(path, 'r', encoding = 'utf-8') as f:
                self.blob = f.read()
            self.parse()

    def parse(self):
        regex1 = re.compile('^([A-Z0-9_]+)="([^"]*)"')
        regex2 = re.compile('^([A-Z0-9_]+)=([^\n]*)')
        for line in self.blob.split('\n'):
            m = regex1.match(line)
            if not m:
                m = regex2.match(line)
            if not m:
                continue
            self[m.group(1)] = m.group(2)


def get_esp_path():
    """ query bootctl to get ESP path """
    result = subprocess.run([ 'bootctl', '--print-esp-path' ],
                            stdout = subprocess.PIPE, check = True)
    return result.stdout.decode().strip('\n')
