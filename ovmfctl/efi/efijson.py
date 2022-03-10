#!/usr/bin/python
""" json support for efi """
import json

from ovmfctl.efi import efivar

# pylint: disable=no-self-use
class EfiJSONEncoder(json.JSONEncoder):
    """  serialise efi data types as json """

    def efivar(self, o):
        retval = {
            'name' : str(o.name),
            'guid' : str(o.guid),
            'attr' : int(o.attr),
            'data' : bytes(o.data).hex(),
        }
        if o.time:
            retval['time'] = o.bytes_time().hex()
        return retval

    def default(self, o):
        if isinstance(o, efivar.EfiVar):
            return self.efivar(o)
        return json.JSONEncoder.default(self, o)
