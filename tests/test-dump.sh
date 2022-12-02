#!/bin/sh

# find images in the system
images=""
for file in \
    /usr/share/edk2/ovmf/*.fd \
    /usr/share/edk2/aarch64/*.fd \
; do
    if test -f "$file"; then
        images="$images $file"
    fi
done

# run tests
set -ex
virt-fw-dump --help
for file in $images; do
    virt-fw-dump -i $file
    virt-fw-dump -i $file --volume-hashes
done
