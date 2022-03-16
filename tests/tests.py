import os
import json
import unittest

from ovmfctl.efi import edk2
from ovmfctl.efi import efijson

VARS_EMPTY   = "/usr/share/OVMF/OVMF_VARS.fd"
VARS_SECBOOT = "/usr/share/OVMF/OVMF_VARS.secboot.fd"

class TestsEdk2(unittest.TestCase):

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no empty vars file')
    def test_enroll(self):
        store = edk2.Edk2VarStore(VARS_EMPTY)
        varlist = store.get_varlist()
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()
        varlist.enable_secureboot()
        blob = store.bytes_varstore(varlist)

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no secboot vars file')
    def test_json(self):
        store = edk2.Edk2VarStore(VARS_SECBOOT)
        varlist = store.get_varlist()
        j = json.dumps(varlist, cls=efijson.EfiJSONEncoder, indent = 4)
        l = json.loads(j, object_hook = efijson.efi_decode)

if __name__ == '__main__':
    unittest.main()
