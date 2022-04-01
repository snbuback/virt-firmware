
Tools for ovmf / armvirt firmware volumes
=========================================

This is a small collection of tools for edk2 firmware images.  They
support decoding and printing the content of firmware volumes.
Variable stores (OVMF_VARS.fd) can be modified, for example to enroll
secure boot certificates.


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


host-efi-vars
-------------

Read efi variables from linux efivarfs and decode/print them.


install
-------

Release: `pip3 install virt-firmware`

Snapshot: `pip3 install git+https://gitlab.com/kraxel/virt-firmware.git`


TODO list
---------

 * Add more documentation.
