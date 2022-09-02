#!/bin/bash

# create work dir
work=$(mktemp --directory /tmp/test-vars-XXXXXXXXXX)
trap "rm -rf $work" EXIT

# run tests
set -ex
virt-fw-vars --help
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.secboot.fd --print --hexdump --extract-certs
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.fd -o ${work}/vars-1.fd --output-json ${work}/vars.json --enroll-redhat --secure-boot
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.fd -o ${work}/vars-2.fd --set-json ${work}/vars.json
diff ${work}/vars-1.fd ${work}/vars-2.fd
virt-fw-vars -i ${work}/vars-1.fd --print --verbose
virt-fw-vars --enroll-redhat --secure-boot --output-aws ${work}/vars.aws
virt-fw-vars -i ${work}/vars.aws --print --verbose
rm -f *.pem
