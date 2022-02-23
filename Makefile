
PYLINT_OPTS	:=
#PYLINT_OPTS	+= --py-version 3.6
PYLINT_OPTS	+= -d invalid-name

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) ovmfctl/

install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall ovmfctl

clean:
	rm -rf build ovmfctl.egg-info
	rm -rf *~ ovmfctl/*~ ovmfctl/efi/*~
	rm -rf *~ ovmfctl/__pycache__  ovmfctl/efi/__pycache__
