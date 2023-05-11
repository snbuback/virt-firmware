#/usr/bin/python3

from virt.firmware.bootcfg import bootcfg

class LinuxEfiBootConfig(bootcfg.EfiBootConfig):
    """ read efi boot configuration from linux sysfs """

    def __init__(self):
        super().__init__()
        self.varstore = None
        self.linux_init()

    def linux_read_variable(self, name):
        return self.varstore.get_variable(name, guids.EfiGlobalVariable)

    def linux_wite_variable(self, var):
        self.varstore.set_variable(var)

    def linux_write_entry(self, nr):
        var = efivar.EfiVar(ucs16.from_string(f'Boot{nr:04X}'),
                            guid = guids.parse_str(guids.EfiGlobalVariable),
                            data = bytes(self.bentr[nr]))
        self.varstore.set_variable(var)

    def linux_remove_entry(self, nr):
        name = f'Boot{nr:04X}'
        self.varstore.del_variable(name, guids.EfiGlobalVariable)

    def linux_update_next(self):
        if not self.bnext_updated:
            return
        if self.bnext is None:
            self.varstore.del_variable('BootNext', guids.EfiGlobalVariable)
            return
        var = efivar.EfiVar(ucs16.from_string('BootNext'),
                            guid = guids.parse_str(guids.EfiGlobalVariable))
        var.set_boot_next(self.bnext)
        self.varstore.set_variable(var)

    def linux_update_order(self):
        if not self.blist_updated:
            return
        var = efivar.EfiVar(ucs16.from_string('BootOrder'),
                            guid = guids.parse_str(guids.EfiGlobalVariable))
        var.set_boot_order(self.blist)
        self.varstore.set_variable(var)

    def linux_init(self):
        self.varstore = linux.LinuxVarStore()
        self.bootorder = self.linux_read_variable('BootOrder')
        self.bootcurrent = self.linux_read_variable('BootCurrent')
        self.bootnext = self.linux_read_variable('BootNext')
        self.parse_boot_variables()
        self.add_unused_entries(self.varstore.scan[guids.EfiGlobalVariable])
        for nr in self.bentr.keys():
            var = self.linux_read_variable(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)
