
PYLINT_OPTS	:=
#PYLINT_OPTS	+= --py-version 3.6	# matches setup.py declaration
PYLINT_OPTS	+= -d invalid-name	# using efi-style names in some places
PYLINT_OPTS	+= -d unused-variable	# happens often when unpacking structss
PYLINT_OPTS	+= -d too-many-locals	# happens when unpacking structss
PYLINT_OPTS	+= -d deprecated-module			# TODO
PYLINT_OPTS	+= -d missing-function-docstring	# TODO

PKG_VERSION	:= $(shell awk '/version/ { print $$3 }' setup.cfg)
PKG_TARBALL	:= dist/ovmfctl-$(PKG_VERSION).tar.gz

FW_IMAGE	:= $(wildcard /usr/share/edk2/ovmf/*.fd)
FW_IMAGE	+= $(wildcard /usr/share/edk2/aarch64/*.fd)

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) ovmfctl/

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
	python3 -m pip uninstall ovmfctl

test: test-ovmfdump test-ovmfctl test-unittest

test-ovmfdump:
	ovmfdump --help
	for i in $(FW_IMAGE); do ovmfdump -i $$i || exit 1; done

test-ovmfctl:
	ovmfctl --help
	ovmfctl -i /usr/share/OVMF/OVMF_VARS.secboot.fd --print --hexdump --extract-certs
	ovmfctl -i /usr/share/OVMF/OVMF_VARS.fd -o vars-1.fd --write-json vars.json --enroll-redhat --secure-boot
	ovmfctl -i /usr/share/OVMF/OVMF_VARS.fd -o vars-2.fd --set-json vars.json
	diff vars-1.fd vars-2.fd
	ovmfctl -i vars-1.fd --print --verbose
	rm -f vars-1.fd vars-2.fd vars.json *.pem

test-unittest:
	python3 tests/tests.py

clean:
	rm -rf build ovmfctl.egg-info $(PKG_TARBALL) rpms dist
	rm -rf *~ ovmfctl/*~ ovmfctl/efi/*~
	rm -rf *~ ovmfctl/__pycache__  ovmfctl/efi/__pycache__
