
PYLINT_OPTS	:=
#PYLINT_OPTS	+= --py-version 3.6	# matches setup.py declaration
PYLINT_OPTS	+= -d invalid-name	# using efi-style names in some places
PYLINT_OPTS	+= -d unused-variable	# happens often when unpacking structss
PYLINT_OPTS	+= -d too-many-locals	# happens when unpacking structss
PYLINT_OPTS	+= -d deprecated-module			# TODO
PYLINT_OPTS	+= -d missing-function-docstring	# TODO

PKG_VERSION	:= $(shell awk '/version/ { print $$3 }' setup.cfg)
PKG_VERNAME	:= ovmfctl-$(PKG_VERSION)
PKG_TARBALL	:= $(PKG_VERNAME).tar.gz

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) ovmfctl/

tarball $(PKG_TARBALL):
	git archive --prefix=$(PKG_VERNAME)/ HEAD | gzip > $(PKG_TARBALL)

rpm package: $(PKG_TARBALL)
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

clean:
	rm -rf build ovmfctl.egg-info $(PKG_TARBALL) rpms
	rm -rf *~ ovmfctl/*~ ovmfctl/efi/*~
	rm -rf *~ ovmfctl/__pycache__  ovmfctl/efi/__pycache__
