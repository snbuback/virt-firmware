#!/usr/bin/python
""" efi ucs-16 encoding and decoding """

import struct

def from_ucs16(data, offset):
    """
    convert ucs-16 bytes to string
    supports ascii only
    """
    pos = offset
    astr = ""
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        if unichar[0] == 0:
            break
        if unichar[0] >= 128:
            astr += "?"
        else:
            astr += f'{unichar[0]:c}'
        pos += 2
    return astr

def get_size(data, offset):
    """
    return ucs-16 string size, including the
    terminating NULL word, in bytes.
    """
    pos = offset
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        pos += 2
        if unichar[0] == 0:
            break
    return pos - offset

def to_ucs16(astr):
    """
    convert ascii string to ucs-16 bytes
    also appends terminating null word
    """
    ustr = b''
    for char in list(astr):
        ustr += char.encode()
        ustr += b'\x00'
    ustr += b'\x00\x00'
    return ustr
