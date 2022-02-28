
Tools for ovmf / armvirt firmware volumes
=========================================

ovmfdump
--------

Decodes and prints the content of firmware volumes.

Usage: `ovmfdump -i <file>`.

ovmfctl
-------

Print and edit variable store volumes.
Currently focused on enrolling certificates and enabling secure boot.

Print variables: `ovmfctl -i <file> --print`.

Enroll certifiactes:
```
ovmfctl --input <template> \
        --output <vars> \
        --enroll-redhat \
        --secure-boot
```

Try `ovmfctl --help` for more usage information.

Install
-------

Release: `pip3 install ovmfctl`

Snapshot: `pip3 install git+https://gitlab.com/kraxel/ovmfctl.git`

TODO list
---------

 * Modularize code.
 * Add documentation.
