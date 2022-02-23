
default:
	@echo "targets: install uninstall clean"

lint pylint:
	pylint --py-version=3.6 -d invalid-name ovmfctl/

install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall ovmfctl

clean:
	rm -rf build ovmfctl.egg-info
	rm -rf *~ ovmfctl/*~ ovmfctl/efi/*~
	rm -rf *~ ovmfctl/__pycache__  ovmfctl/efi/__pycache__
