#!/usr/bin/python
"""
efi device path decoder

EFI_DEVICE_PATH_PROTOCOL (Protocol/DevicePath.h)
"""

import struct
import collections

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16

class DevicePathElem:
    """ class reprsenting an efi device path element """

    def __init__(self, data):
        (self.devtype, self.subtype, self.size) = struct.unpack_from('=BBH', data)
        self.data = data[ 4 : self.size ]

    def hw(self):
        if self.subtype == 0x01:
            (func, dev) = struct.unpack_from('=BB', self.data)
            return f'PCI(device={dev:02x}:{func:x})'
        if self.subtype == 0x04:
            guid = guids.parse_bin(self.data, 0)
            return f'VendorHW({guid})'
        return f'HW(subtype=0x{self.subtype:x})'

    def acpi(self):
        if self.subtype == 0x01:
            (hid, uid) = struct.unpack_from('=LL', self.data)
            return f'ACPI(hid=0x{hid:x},uid=0x{uid:x})'
        return f'ACPI(subtype=0x{self.subtype:x})'

    # pylint: disable=too-many-return-statements
    def msg(self):
        if self.subtype == 0x02:
            (pun, lun) = struct.unpack_from('=HH', self.data)
            return f'SCSI(pun={pun},lun={lun})'
        if self.subtype == 0x0b:
            return 'MAC()'
        if self.subtype == 0x0c:
            return 'IPv4()'
        if self.subtype == 0x0d:
            return 'IPv6()'
        if self.subtype == 0x12:
            (port, mul, lun) = struct.unpack_from('=HHH', self.data)
            return f'SATA(port={port})'
        if self.subtype == 0x18:
            return 'URI()'
        return f'Msg(subtype=0x{self.subtype:x})'

    def media(self):
        if self.subtype == 0x01:
            (pnr, pstart, pend) = struct.unpack_from('=LQQ', self.data)
            return f'Partition(nr={pnr})'
        if self.subtype == 0x04:
            path = ucs16.from_ucs16(self.data, 0)
            return f'FilePath({path})'
        if self.subtype == 0x06:
            guid = guids.parse_bin(self.data, 0)
            return f'FvFileName({guid})'
        if self.subtype == 0x07:
            guid = guids.parse_bin(self.data, 0)
            return f'FvName({guid})'
        return f'Media(subtype=0x{self.subtype:x})'

    def __str__(self):
        if self.devtype == 0x01:
            return self.hw()
        if self.devtype == 0x02:
            return self.acpi()
        if self.devtype == 0x03:
            return self.msg()
        if self.devtype == 0x04:
            return self.media()
        return f'Unknown(type=0x{self.devtype:x},subtype=0x{self.subtype:x})'

class DevicePath(collections.UserList):
    """ class reprsenting an efi device path """

    def __init__(self, data):
        super().__init__()
        pos = 0
        while pos < len(data):
            elem = DevicePathElem(data[pos:])
            if elem.devtype == 0x7f:
                break
            self.append(elem)
            pos += elem.size

    def __str__(self):
        return "/".join(map(str, list(self)))
