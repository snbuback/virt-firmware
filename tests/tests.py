import os
import unittest

from ovmfctl.efi import edk2

EMPTY_VARS = "/usr/share/OVMF/OVMF_VARS.fd"

@unittest.skipUnless(os.path.exists(EMPTY_VARS), 'no VARS file')
class TestsEdk2(unittest.TestCase):

    def test_enroll(self):
        store = edk2.Edk2VarStore(EMPTY_VARS)
        varlist = store.get_varlist()
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()
        varlist.enable_secureboot()
        blob = store.bytes_varstore(varlist)

if __name__ == '__main__':
    unittest.main()
