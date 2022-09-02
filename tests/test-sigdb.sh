#!/bin/sh

certdb="/etc/pki/ca-trust/extracted/edk2/cacerts.bin"

# run tests
set -ex
virt-fw-sigdb --help
if test -f "${certdb}"; then
    virt-fw-sigdb --input "${certdb}" --print
fi
