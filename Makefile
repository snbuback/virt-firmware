
default:
	@echo "targets: install clean"

install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall ovmfctl

clean:
	rm -rf *~ ovmfctl/*~ build ovmfctl.egg-info
