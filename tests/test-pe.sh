#!/bin/sh

kernel="/boot/vmlinuz-$(uname -r)"
shim="$(echo /boot/efi/EFI/*/shim*.efi)"

# run tests
set -ex
pe-dumpinfo --help
pe-listsigs --help
pe-addsigs --help
for file in ${kernel} ${shim}; do
    if test -f "${file}"; then
        pe-listsigs "${file}"
    fi
done
