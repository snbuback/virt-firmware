#!/usr/bin/python
""" efi variables """

import struct
import datetime

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16
from ovmfctl.efi import devpath
from ovmfctl.efi import siglist

##################################################################################################
# constants

# variable attributes
EFI_VARIABLE_NON_VOLATILE                          = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS                    = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS                        = 0x00000004
EFI_VARIABLE_HARDWARE_ERROR_RECORD                 = 0x00000008
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            = 0x00000010  # deprecated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
EFI_VARIABLE_APPEND_WRITE                          = 0x00000040

EFI_VARIABLE_DEFAULT = (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS)

efivar_defaults = {
    'SecureBootEnable' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiSecureBootEnableDisable,
    },
    'CustomMode' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiCustomModeEnable,
    },
    'PK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'KEK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'db' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
    'dbx' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
}

sigdb_names = ("PK", "KEK", "db", "dbx", "MokList")
bool_names  = ('SecureBootEnable', 'CustomMode')
ascii_names = ('Lang', 'PlatformLang')
blist_names = ('BootOrder', 'BootNext')

##################################################################################################

# pylint: disable=too-many-arguments,too-many-instance-attributes
class EfiVar:
    """  class for efi variables"""

    def __init__(self, name,
                 guid = None,
                 attr = None,
                 data = b'',
                 count = 0,
                 pkidx = 0):
        self.name = name
        self.guid = guid
        self.attr = attr
        self.data = data
        self.count = count
        self.pkidx = pkidx
        self.time = None
        self.sigdb = None

        defaults = efivar_defaults.get(str(name))
        if self.guid is None:
            if defaults:
                self.guid = guids.parse_str(defaults['guid'])
            else:
                raise RuntimeError("guid missing")
        if self.attr is None:
            if defaults:
                self.attr = defaults['attr']
            else:
                self.attr = EFI_VARIABLE_DEFAULT

        if str(self.name) in sigdb_names:
            self.sigdb = siglist.EfiSigDB(self.data)

    def parse_time(self, data, offset):
        """ parse struct EFI_TIME """
        (year, month, day, hour, minute, second, ns, tz, dl) = \
            struct.unpack_from("=HBBBBBxLhBx", data, offset)
        if year:
            self.time = datetime.datetime(year, month, day,
                                          hour, minute, second,
                                          int(ns / 1000))
        else:
            self.time = None

    def bytes_time(self):
        """ generate struct EFI_TIME """
        if self.time is None:
            return b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        return struct.pack("=HBBBBBxLhBx",
                           self.time.year, self.time.month, self.time.day,
                           self.time.hour, self.time.minute, self.time.second,
                           self.time.microsecond * 1000,
                           0, 0)

    def update_time(self):
        if not self.attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS:
            return
        self.time = datetime.datetime.now(datetime.timezone.utc)

    def sigdb_clear(self):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb = siglist.EfiSigDB()
        self.data = bytes(self.sigdb)
        self.update_time()

    def sigdb_add_cert(self, guid, filename):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb.add_cert(guid, filename)
        self.data = bytes(self.sigdb)
        self.update_time()

    def sigdb_add_dummy(self, guid):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb.add_dummy(guid)
        self.data = bytes(self.sigdb)
        self.update_time()

    def set_bool(self, value):
        if value:
            self.data = b'\x01'
        else:
            self.data = b'\x00'
        self.update_time()

    def fmt_bool(self):
        if self.data[0]:
            return 'bool: ON'
        return 'bool: off'

    def fmt_ascii(self):
        string = self.data.decode().rstrip('\0')
        return f'ascii: {string}'

    def fmt_boot_entry(self):
        (attr, pathsize) = struct.unpack_from('=LH', self.data)
        name = ucs16.from_ucs16(self.data, 6)
        path = self.data[ name.size() + 6 :
                          name.size() + 6 + pathsize ]
        obj = devpath.DevicePath(path)
        return f'boot entry: name={name} devpath={obj}'

    def fmt_boot_list(self):
        bootlist = []
        for pos in range(len(self.data) >> 1):
            nr = struct.unpack_from('=H', self.data, pos * 2)
            bootlist.append(f'{nr[0]:04d}')
            desc= ", ".join(bootlist)
        return f'boot order: {desc}'

    def fmt_data(self):
        name = str(self.name)
        if name in bool_names:
            return self.fmt_bool()
        if name in ascii_names:
            return self.fmt_ascii()
        if name in blist_names:
            return self.fmt_boot_list()
        if name.startswith('Boot0'):
            return self.fmt_boot_entry()

        if len(self.data) in (1, 2, 4, 8):
            name = {
                1 : 'byte',
                2 : 'word',
                4 : 'dword',
                8 : 'qword',
            }
            n = name[len(self.data)]
            d = bytearray(self.data)
            d.reverse()
            return f'{n}: 0x{d.hex()}'

        return None
