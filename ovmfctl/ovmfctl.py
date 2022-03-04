#!/usr/bin/python
""" print and edit ovmf varstore files """
import sys
import struct
import pprint
import optparse
import datetime
import pkg_resources

from cryptography import x509

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16
from ovmfctl.efi import devpath
from ovmfctl.efi import siglist

##################################################################################################
# constants

# variable attributes
EFI_VARIABLE_NON_VOLATILE                          = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS                    = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS                        = 0x00000004
EFI_VARIABLE_HARDWARE_ERROR_RECORD                 = 0x00000008
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            = 0x00000010  # deprecated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
EFI_VARIABLE_APPEND_WRITE                          = 0x00000040

vars_settings = {
    'SecureBootEnable' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiSecureBootEnableDisable,
    },
    'CustomMode' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiCustomModeEnable,
    },
    'PK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'KEK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'db' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
    'dbx' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
}

var_template = {
    'guid'       : b'FIXME',
    'name'       : b'FIXME',
    'attr'       : 0,
    'count'      : 0,
    'pkidx'      : 0,
    'data'       : b'',
    'time'       : None,
}


##################################################################################################
# parse stuff

def parse_time(data, offset):
    (year, month, day, hour, minute, second, ns, tz, dl) = \
        struct.unpack_from("=HBBBBBxLhBx", data, offset)
    if year == 0:
        return None
    return datetime.datetime(year, month, day,
                             hour, minute, second, int(ns / 1000))

def parse_vars(data, start, end):
    pos = start
    varlist = {}
    while pos < end:
        (magic, state, attr, count) = struct.unpack_from("=HBxLQ", data, pos)
        if magic != 0x55aa:
            break
        (pk, nsize, dsize) = struct.unpack_from("=LLL", data, pos + 32)

        if state == 0x3f:
            var = {
                'attr'  : attr,
                'count' : count,
                'pkidx' : pk,
            }
            var['time'] = parse_time(data, pos + 16)

            var['guid'] = guids.parse_bin(data, pos + 44)
            var['name'] = ucs16.from_ucs16(data, pos + 44 + 16)
            var['data'] = data[pos + 44 + 16 + nsize :
                               pos + 44 + 16 + nsize + dsize]

            name = str(var['name'])
            varlist[name] = var

            if name in ("PK", "KEK", "db", "dbx", "MokList"):
                var['sigdb'] = siglist.EfiSigDB(var['data'])

        pos = pos + 44 + 16 + nsize + dsize
        pos = (pos + 3) & ~3 # align
    return varlist

def parse_varstore(file, data, start):
    guid = guids.parse_bin(data, start)
    (size, storefmt, state) = struct.unpack_from("=LBB", data, start + 16)
    print(f'varstore={guids.name(guid)} size=0x{size:x} '
          f'format=0x{storefmt:x} state=0x{state:x}')
    if str(guid) != guids.AuthVars:
        print(f"ERROR: {file}: unknown varstore guid")
        sys.exit(1)
    if storefmt != 0x5a:
        print(f"ERROR: {file}: unknown varstore format")
        sys.exit(1)
    if state != 0xfe:
        print(f"ERROR: {file}: unknown varstore state")
        sys.exit(1)
    return (start + 16 + 12, start + size)

def parse_volume(file, data):
    guid = guids.parse_bin(data, 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
        struct.unpack_from("=QLLHHHxBLL", data, 32)
    print(f'vol={guids.name(guid)} vlen=0x{vlen:x} rev={rev} '
          f'blocks={blocks}*{blksize} (0x{blocks * blksize:x})')
    if sig != 0x4856465f:
        print(f"ERROR: {file}: not a firmware volume")
        sys.exit(1)
    if str(guid) != guids.NvData:
        print(f"ERROR: {file}: not a variable store")
        sys.exit(1)
    return parse_varstore(file, data, hlen)


##################################################################################################
# print stuff, debug logging

def print_hexdump(data, start, end):
    hstr = ''
    astr = ''
    pos = start
    count = 0
    while True:
        hstr += f'{data[start+count]:02x} '
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            astr += f'{data[start+count]:c}'
        else:
            astr += '.'
        count += 1
        if count % 4 == 0:
            hstr += ' '
            astr += ' '
        if count % 16 == 0 or start+count == end:
            print(f'    {pos:06x}:  {hstr:52s} {astr}')
            hstr = ''
            astr = ''
            pos += 16
        if count == 256 or start+count == end:
            break
    if start+count < end:
        print(f'    {pos:06x}: [ ... ]')

def print_bool(var):
    if var['data'][0]:
        print("    bool: ON")
    else:
        print("    bool: off")

def print_boot_entry(var):
    (attr, pathsize) = struct.unpack_from('=LH', var['data'])
    name = ucs16.from_ucs16(var['data'], 6)
    pathoffset = name.size() + 6
    devicepath = devpath.DevicePath(var['data'][pathoffset: pathoffset + pathsize])
    print(f'    boot entry: name={name} devicepath={devicepath}')

def print_boot_list(var):
    bootlist = []
    for pos in range(len(var['data']) >> 1):
        nr = struct.unpack_from('=H', var['data'], pos * 2)
        bootlist.append(f'{nr[0]:04d}')
    desc= ", ".join(bootlist)
    print(f'    boot order: {desc}')

def print_ascii(var):
    print(f"    string: {var['data'].decode()}")

def print_sigdb(var):
    for item in var['sigdb']:
        name = guids.name(item.guid)
        count = len(item)
        print(f'    list type={name} count={count}')
        if item.x509:
            cn = item.x509.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
            print(f'      x509 CN={cn.value}')

print_funcs = {
    'SecureBootEnable' : print_bool,
    'CustomMode'       : print_bool,

    'Lang'             : print_ascii,
    'PlatformLang'     : print_ascii,

    'BootOrder'        : print_boot_list,
    'BootNext'         : print_boot_list,
    'Boot0000'         : print_boot_entry,
    'Boot0001'         : print_boot_entry,
    'Boot0002'         : print_boot_entry,
    'Boot0003'         : print_boot_entry,
    'Boot0004'         : print_boot_entry,
    'Boot0005'         : print_boot_entry,
    'Boot0006'         : print_boot_entry,
    'Boot0007'         : print_boot_entry,
    'Boot0008'         : print_boot_entry,
    'Boot0009'         : print_boot_entry,
}

def print_var(var, verbose, hexdump):
    name = str(var['name'])
    gname = guids.name(var['guid'])
    size = len(var['data'])
    print(f'  - name={name} guid={gname} size={size}')
    pfunc = print_funcs.get(name)
    if pfunc:
        pfunc(var)
    if var.get('sigdb'):
        print_sigdb(var)
    if verbose:
        print("----- raw -----")
        pprint.pprint(var)
        print("----- end -----")
    if hexdump:
        print_hexdump(var['data'], 0, len(var['data']))

def print_vars(varlist, verbose, hexdump):
    print("# printing variables ...")
    for (key, item) in varlist.items():
        print_var(item, verbose, hexdump)
    print("# ... done")


##################################################################################################
# write vars

def update_data_from_sigdb(var):
    sigdb = var.get('sigdb')
    if not sigdb:
        return
    var['data'] = bytes(sigdb)

def write_time(time):
    if time is None:
        return b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    return struct.pack("=HBBBBBxLhBx",
                       time.year, time.month, time.day,
                       time.hour, time.minute, time.second,
                       time.microsecond * 1000,
                       0, 0)

def write_var(var):
    blob = struct.pack("=HBxLQ",
                       0x55aa, 0x3f,
                       var['attr'],
                       var['count'])
    blob += write_time(var['time'])
    blob += struct.pack("=LLL",
                        var['pkidx'],
                        var['name'].size(),
                        len(var['data']))
    blob += var['guid'].bytes_le
    blob += bytes(var['name'])
    blob += var['data']
    while len(blob) & 3:
        blob += b'\0'
    return blob

def vars_delete(varlist, delete):
    for item in delete:
        if varlist.get(item):
            print(f'# delete variable: {item}')
            del varlist[item]
        else:
            print(f'# WARNING: variable {item} not found')

def var_update_time(var):
    if not var['attr'] & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS:
        return
    var['time'] = datetime.datetime.now(datetime.timezone.utc)

def var_create(varlist, name):
    cfg = vars_settings.get(name)
    if not cfg:
        print(f'ERROR: unknown variable {name}')
        sys.exit(1)

    print(f'# create variable {name}')
    var = var_template.copy()
    var['guid'] = guids.parse_str(cfg['guid'])
    var['name'] = ucs16.from_string(name)
    var['attr'] = cfg['attr']
    varlist[name] = var
    return var

def var_set_bool(varlist, name, value):
    var = varlist.get(name)
    if not var:
        var = var_create(varlist, name)

    if value:
        print(f'# set variable {name}: True')
        var['data'] = b'\x01'
    else:
        print(f'# set variable {name}: False')
        var['data'] = b'\x00'
    var_update_time(var)

def var_add_cert(varlist, name, owner, filename, replace = False):
    var = varlist.get(name)
    if not var:
        var = var_create(varlist, name)
    if not var.get('sigdb') or replace:
        print(f'# init/clear {name} sigdb')
        var['sigdb'] = siglist.EfiSigDB()

    print(f'# add {name} cert {filename}')
    var['sigdb'].add_cert(guids.parse_str(owner), filename)
    update_data_from_sigdb(var)
    var_update_time(var)

def var_add_dummy_dbx(varlist, owner):
    var = varlist.get('dbx')
    if var:
        return

    print("# add dummy dbx entry")
    var = var_create(varlist, 'dbx')
    var['sigdb'] = siglist.EfiSigDB()
    var['sigdb'].add_dummy(guids.parse_str(owner))
    update_data_from_sigdb(var)
    var_update_time(var)


##################################################################################################
# main

def enable_secureboot(varlist):
    var_add_dummy_dbx(varlist, guids.OvmfEnrollDefaultKeys)
    var_set_bool(varlist, 'SecureBootEnable', True)
    var_set_bool(varlist, 'CustomMode', False)

def platform_redhat(varlist):
    redhat_pk = pkg_resources.resource_filename('ovmfctl',
                                                'certs/RedHatSecureBootPKKEKkey1.pem')
    var_add_cert(varlist, 'PK', guids.OvmfEnrollDefaultKeys, redhat_pk, True)
    var_add_cert(varlist, 'KEK', guids.OvmfEnrollDefaultKeys, redhat_pk, True)
    var_add_dummy_dbx(varlist, guids.OvmfEnrollDefaultKeys)

def microsoft_keys(varlist):
    ms_kek = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftCorporationKEKCA2011.pem')
    ms_win = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftWindowsProductionPCA2011.pem')
    ms_3rd = pkg_resources.resource_filename('ovmfctl',
                                             'certs/MicrosoftCorporationUEFICA2011.pem')
    var_add_cert(varlist, 'KEK', guids.MicrosoftVendor, ms_kek, False)
    var_add_cert(varlist, 'db', guids.MicrosoftVendor, ms_win, False) # windows
    var_add_cert(varlist, 'db', guids.MicrosoftVendor, ms_3rd, False) # 3rd party (shim.efi)

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_option('--extract-certs', dest = 'extract',
                      action = 'store_true', default = False,
                      help = 'extract all certificates')
    parser.add_option('-d', '--delete', dest = 'delete',
                      action = 'append', type = 'string',
                      help = 'delete variable VAR, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-true', dest = 'set_true',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to true, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-false', dest = 'set_false',
                      action = 'append', type = 'string',
                      help = 'set variable VAR to false, can be specified multiple times',
                      metavar = 'VAR')
    parser.add_option('--set-pk', dest = 'pk',  nargs = 2,
                      help = 'set PK to x509 cert, loaded in pem format ' +
                      'from FILE and with owner GUID',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-kek', dest = 'kek',  action = 'append', nargs = 2,
                      help = 'add x509 cert to KEK, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-db', dest = 'db',  action = 'append', nargs = 2,
                      help = 'add x509 cert to db, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-mok', dest = 'mok',  action = 'append', nargs = 2,
                      help = 'add x509 cert to MokList, loaded in pem format ' +
                      'from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--enroll-redhat', dest = 'redhat',
                      action = 'store_true', default = False,
                      help = 'enroll default certificates for redhat platform')
    parser.add_option('--sb', '--secure-boot', dest = 'secureboot',
                      action = 'store_true', default = False,
                      help = 'enable secure boot mode')
    parser.add_option('-p', '--print', dest = 'print',
                      action = 'store_true', default = False,
                      help = 'print varstore')
    parser.add_option('-v', '--verbose', dest = 'verbose',
                      action = 'store_true', default = False,
                      help = 'print varstore verbosely')
    parser.add_option('-x', '--hexdump', dest = 'hexdump',
                      action = 'store_true', default = False,
                      help = 'print variable hexdumps')
    parser.add_option('-o', '--output', dest = 'output', type = 'string',
                      help = 'write edk2 vars to FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    if not options.input:
        print("ERROR: no input file specified (try -h for help)")
        sys.exit(1)

    print(f'# reading varstore from {options.input}')
    with open(options.input, "rb") as f:
        infile = f.read()

    (start, end) = parse_volume(options.input, infile)
    print(f'var store range: 0x{start:x} -> 0x{end:x}')
    varlist = parse_vars(infile, start, end)

    if options.delete:
        vars_delete(varlist, options.delete)

    if options.set_true:
        for item in options.set_true:
            varlist[item]['data'] = b'\x01'

    if options.set_false:
        for item in options.set_false:
            varlist[item]['data'] = b'\x00'

    if options.redhat:
        platform_redhat(varlist)
        microsoft_keys(varlist)

    if options.pk:
        var_add_cert(varlist, 'PK', options.pk[0], options.pk[1], True)

    if options.kek:
        for item in options.kek:
            var_add_cert(varlist, 'KEK', item[0], item[1])

    if options.db:
        for item in options.db:
            var_add_cert(varlist, 'db', item[0], item[1])

    if options.mok:
        for item in options.mok:
            var_add_cert(varlist, 'MokList', item[0], item[1])

    if options.secureboot:
        enable_secureboot(varlist)

    if options.print:
        print_vars(varlist, options.verbose, options.hexdump)

    if options.output:
        outfile = infile[:start]
        for (key, item) in varlist.items():
            outfile += write_var(item)

        if len(outfile) > end:
            print("ERROR: varstore is too small")
            sys.exit(1)

        outfile += b''.zfill(end - len(outfile))
        outfile += infile[end:]

        print(f'# writing varstore to {options.output}')
        with open(options.output, "wb") as f:
            f.write(outfile)

    return 0

if __name__ == '__main__':
    sys.exit(main())
