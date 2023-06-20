
# Tools for ovmf / armvirt firmware volumes

This is a small collection of tools for edk2 firmware images.  They
support decoding and printing the content of firmware volumes.
Variable stores (OVMF_VARS.fd) can be modified, for example to enroll
secure boot certificates.


## virt-fw-dump

Decodes and prints the content of firmware volumes.

Usage: `virt-fw-dump -i <file>`.

Try `virt-fw-dump --help` for more info, there are some options to
filter output.


## virt-fw-vars

Print and edit variable store volumes.
Currently focused on enrolling certificates and enabling secure boot.

Print variables: `virt-fw-vars -i <file> --print`.

Enroll certificates:
```
virt-fw-vars \
    --input <template> \
    --output <vars> \
    --enroll-redhat \
    --secure-boot
```
Try `virt-fw-vars --help` for more usage information.

virt-fw-vars can handle edk2 variable stores (which are flash firmware
volumes) and AWS uefi variable stores.  The input format is detected
automatically and the same format is used for output.

Working with edk2 variable stores requires a firmware volume as input.
Typically the OVMF_VARS.fd file created when building OVMF is used for
that (it is an empty variable store).

aws variable stores can also be created from scratch and written to a
file with using the `--output-aws` option.


## virt-fw-sigdb

Print and edit efi signature database files, example:
```
virt-fw-sigdb -i /etc/pki/ca-trust/extracted/edk2/cacerts.bin --print
```
Try `virt-fw-sigdb --help` for more usage information.


## host-efi-vars

Read efi variables from linux efivarfs and decode/print them.


## kernel-bootcfg

Manage efi boot configuration for UKIs (unified kernel images) when
using direkt boot (without boot loader like grub or systemd-boot).


## pe-dumpinfo

Information dump for pe (the format used by efi) binaries.


## pe-listsigs

List signatures and certificate chain for pe binaries.
Can also extract certificates & signatures.


## using the python modules

There isn't much documentation yet, sorry.  Best code reads to get
started are probably the test cases (see `tests/tests.py`) and the
code for the virt-fw-vars utility (see `virt/firmware/vars.py`).


## install

Release: `pip3 install virt-firmware`

Snapshot: `pip3 install git+https://gitlab.com/kraxel/virt-firmware.git`


## TODO list

 * Add more documentation.
