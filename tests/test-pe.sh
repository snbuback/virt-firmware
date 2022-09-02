#!/bin/sh

kernel="/boot/vmlinuz-$(uname -r)"

# run tests
set -ex
pe-dumpinfo --help
pe-listsigs --help
pe-addsigs --help
if test -f "${kernel}"; then
    pe-listsigs "${kernel}"
fi
