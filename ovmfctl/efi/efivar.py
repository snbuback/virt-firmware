#!/usr/bin/python
""" efi variables """

import struct
import datetime

from ovmfctl.efi import guids
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
