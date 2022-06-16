
PYLINT_OPTS	:=
PYLINT_OPTS	+= --py-version 3.6	# matches setup.py declaration
PYLINT_OPTS	+= -d invalid-name	# using efi-style names in some places
PYLINT_OPTS	+= -d unused-variable	# happens often when unpacking structss
PYLINT_OPTS	+= -d too-many-locals	# happens when unpacking structss
PYLINT_OPTS	+= -d R0801		# duplicate-code (simliar cmd line opts)
PYLINT_OPTS	+= -d deprecated-module			# TODO
PYLINT_OPTS	+= -d missing-function-docstring	# TODO
PYLINT_OPTS	+= --extension-pkg-allow-list=crc32c

PKG_VERSION	:= $(shell awk '/version/ { print $$3 }' setup.cfg)
PKG_TARBALL	:= dist/virt-firmware-$(PKG_VERSION).tar.gz

FW_IMAGE	:= $(wildcard /usr/share/edk2/ovmf/*.fd)
FW_IMAGE	+= $(wildcard /usr/share/edk2/aarch64/*.fd)
CERT_DB		:= /etc/pki/ca-trust/extracted/edk2/cacerts.bin

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) virt/firmware

.PHONY: dist
dist tarball $(PKG_TARBALL):
	rm -rf dist
	python3 -m build
	twine check dist/*

rpm rpms package: $(PKG_TARBALL)
	rm -rf rpms
	mkdir -p rpms/src
	pyp2rpm -d rpms/src --srpm $(PKG_TARBALL)
	rpmbuild --rebuild \
		--define "_rpmdir rpms" \
		--define "_srcrpmdir rpms/src" \
		rpms/src/*.src.rpm
	createrepo rpms

install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall virt-firmware

test check: test-dump test-vars test-sigdb test-unittest

test-dump:
	virt-fw-dump --help
	for i in $(FW_IMAGE); do echo "# $$i"; virt-fw-dump -i $$i || exit 1; done

test-vars:
	virt-fw-vars --help
	virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.secboot.fd --print --hexdump --extract-certs
	virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.fd -o vars-1.fd --output-json vars.json --enroll-redhat --secure-boot
	virt-fw-vars -i /usr/share/OVMF/OVMF_VARS.fd -o vars-2.fd --set-json vars.json
	diff vars-1.fd vars-2.fd
	virt-fw-vars -i vars-1.fd --print --verbose
	virt-fw-vars --enroll-redhat --secure-boot --output-aws vars.aws
	virt-fw-vars -i vars.aws --print --verbose
	rm -f vars-1.fd vars-2.fd vars.json vars.aws *.pem

test-sigdb:
	virt-fw-sigdb --help
	if test -f "$(CERT_DB)"; then virt-fw-sigdb --input "$(CERT_DB)" --print; fi

test-unittest:
	python3 tests/tests.py

clean:
	rm -rf build virt_firmware.egg-info $(PKG_TARBALL) rpms dist
	rm -rf *~ virt/firmware/*~ virt/firmware/efi/*~
	rm -rf *~ virt/firmware/__pycache__ virt/firmware/efi/__pycache__
