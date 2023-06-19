#!/bin/bash
set -ex
kernel-bootcfg --help
if test -d /sys/firmware/efi; then
    kernel-bootcfg --show
fi
