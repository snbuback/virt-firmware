#/usr/bin/python3
# pylint: disable=consider-iterating-dictionary
""" experimental efi boot config tool """
import os
import re
import sys
import logging
import argparse
import subprocess

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar
from virt.firmware.efi import devpath
from virt.firmware.efi import bootentry

from virt.firmware.bootcfg import bootcfg
from virt.firmware.bootcfg import linuxcfg


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


########################################################################
# main

def esp_path():
    result = subprocess.run([ 'bootctl', '--print-esp-path' ],
                            stdout = subprocess.PIPE, check = True)
    return result.stdout.decode().strip('\n')

def add_uki(cfg, esp, options):
    if not options.shim:
        logging.error('shim binary not specified')
        sys.exit(1)
    if not options.title:
        logging.error('entry title not specified')
        sys.exit(1)

    efiuki  = esp.efi_filename(options.adduki)
    nr = cfg.find_uki_entry(efiuki)
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
        nr = cfg.add_entry(entry)
        logging.info('Added entry (Boot%04X)', nr)
        if not options.dryrun:
            cfg.linux_write_entry(nr)

    if options.bootnext:
        cfg.set_boot_next(nr)
        if not options.dryrun:
            cfg.linux_update_next()


def remove_uki(cfg, esp, options):
    efiuki = esp.efi_filename(options.removeuki)
    nr = cfg.find_uki_entry(efiuki)
    if nr is None:
        logging.warning('No entry found for %s', options.removeuki)
        return

    logging.info('Removing entry (Boot%04X)', nr)
    cfg.remove_entry(nr)
    if not options.dryrun:
        cfg.linux_remove_entry(nr)
        cfg.linux_update_next()
        cfg.linux_update_order()


def boot_success(cfg, options):
    if cfg.bcurr == cfg.blist[0]:
        logging.info('No update needed, BootCurrent already comes first in BootOrder.')
        return
    logging.info('Add BootCurrent (Boot%04X) to BootOrder', cfg.bcurr)
    cfg.set_boot_order(cfg.bcurr, 0)
    if not options.dryrun:
        cfg.linux_update_order()

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
        cfg = bootcfg.VarStoreEfiBootConfig(options.varsfile)
    else:
        esp = LinuxBlockDev(esp_path())
        cfg = linuxcfg.LinuxEfiBootConfig()
        #print(esp.dev_path_file('/boot/efi/EFI/fedora/shimx64.efi'))

    # apply updates
    if options.adduki:
        add_uki(cfg, esp, options)
    elif options.removeuki:
        remove_uki(cfg, esp, options)
    elif options.bootok:
        boot_success(cfg, options)
    else:
        # default action
        options.show = True

    # print info
    if options.show:
        cfg.print_cfg(options.verbose)

    return 0

if __name__ == '__main__':
    sys.exit(main())
