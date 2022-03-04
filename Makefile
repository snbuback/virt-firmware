
PYLINT_OPTS	:=
#PYLINT_OPTS	+= --py-version 3.6	# matches setup.py declaration
PYLINT_OPTS	+= -d invalid-name	# using efi-style names in some places
PYLINT_OPTS	+= -d unused-variable	# happens often when unpacking structss
PYLINT_OPTS	+= -d too-many-locals	# happens when unpacking structss
PYLINT_OPTS	+= -d deprecated-module			# TODO
PYLINT_OPTS	+= -d missing-function-docstring	# TODO

PKG_VERSION	:= $(shell awk '/version/ { print $$3 }' setup.cfg)
PKG_TARBALL	:= dist/ovmfctl-$(PKG_VERSION).tar.gz

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) ovmfctl/

tarball $(PKG_TARBALL):
	rm -rf dist
	python3 -m build

.PHONY: dist
rpm package dist: $(PKG_TARBALL)
	rm -rf rpms
	mkdir -p rpms/src
	pyp2rpm -d rpms/src --srpm $(PKG_TARBALL)
	rpmbuild --rebuild \
		--define "_rpmdir rpms" \
		--define "_srcrpmdir rpms/src" \
		rpms/src/*.src.rpm
	createrepo rpms
	twine check dist/*

install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall ovmfctl

test: test-ovmfdump test-ovmfctl

test-ovmfdump:
	ovmfdump --help
	ovmfdump -i /usr/share/edk2/aarch64/QEMU_EFI.fd
	ovmfdump -i /usr/share/edk2/aarch64/QEMU_VARS.fd
	ovmfdump -i /usr/share/OVMF/OVMF_CODE.secboot.fd
	ovmfdump -i /usr/share/OVMF/OVMF_VARS.secboot.fd

test-ovmfctl:
	ovmfctl --help
	ovmfctl -i /usr/share/OVMF/OVMF_VARS.secboot.fd --print --hexdump --extract-certs
	ovmfctl -i /usr/share/OVMF/OVMF_VARS.fd -o vars.fd --enroll-redhat --secure-boot
	ovmfctl -i vars.fd --print --verbose
	rm -f vars.fd

clean:
	rm -rf build ovmfctl.egg-info $(PKG_TARBALL) rpms dist
	rm -rf *~ ovmfctl/*~ ovmfctl/efi/*~
	rm -rf *~ ovmfctl/__pycache__  ovmfctl/efi/__pycache__
