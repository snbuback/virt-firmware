
Tools for ovmf / armvirt firmware volumes
=========================================

virt-fw-dump
------------

Decodes and prints the content of firmware volumes.

Usage: `virt-fw-dump -i <file>`.

virt-fw-vars
------------

Print and edit variable store volumes.
Currently focused on enrolling certificates and enabling secure boot.

Print variables: `virt-fw-vars -i <file> --print`.

Enroll certifiactes:
```
virt-fw-vars \
    --input <template> \
    --output <vars> \
    --enroll-redhat \
    --secure-boot
```

Try `virt-fw-vars --help` for more usage information.

Install
-------

Release: `pip3 install virt-firmware`

Snapshot: `pip3 install git+https://gitlab.com/kraxel/virt-firmware.git`

TODO list
---------

 * Modularize code.
 * Add documentation.
