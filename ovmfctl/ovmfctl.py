#!/usr/bin/python
""" print and edit ovmf varstore files """
import os
import sys
import struct
import pprint
import hashlib
import optparse
import datetime
import pkg_resources

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ovmfctl.efi import guids
from ovmfctl.efi import ucs16

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
    'ascii_guid' : 'FIXME',
    'ascii_name' : 'FIXME',
    'guid'       : b'FIXME',
    'name'       : b'FIXME',
    'attr'       : 0,
    'count'      : 0,
    'pkidx'      : 0,
    'data'       : b'',
    'time'       : {
        'year'   : 0,
        'month'  : 0,
        'day'    : 0,
        'hour'   : 0,
        'min'    : 0,
        'ns'     : 0,
        'sec'    : 0,
        'tz'     : 0,
        'dl'     : 0,
    }
}


##################################################################################################
# parse stuff

def parse_time(data, offset):
    (year, month, day, hour, minute, second, ns, tz, dl) = \
        struct.unpack_from("=HBBBBBxLhBx", data, offset)
    time = {
        'year'  : year,
        'month' : month,
        'day'   : day,
        'hour'  : hour,
        'min'   : minute,
        'sec'   : second,
        'ns'    : ns,
        'tz'    : tz,
        'dl'    : dl,
    }
    return time

def extract_cert(var, owner, cert):
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
    filename = var['ascii_name']
    filename += '-' + owner
    filename += '-' + "".join(x for x in cn.value if x.isalnum())
    filename += ".pem"
    if os.path.exists(filename):
        print(f"# WARNNG: exists: {filename}")
        return
    print(f"# writing: {filename}")
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def parse_sigs(var, extract):
    data = var['data']
    pos = 0
    var['siglists'] = []
    while pos < len(data):
        guid = guids.parse(data, pos)
        (lsize, hsize, ssize) = struct.unpack_from("=LLL", data, pos + 16)
        siglist = data[ pos + 16 + 12 + hsize : pos+lsize ]
        sigs = []
        spos = 0
        while spos < len(siglist):
            owner = siglist[ spos : spos + 16 ]
            sdata = siglist[ spos + 16 : spos + ssize ]
            sig = {
                'ascii_guid' : guids.parse(owner, 0),
                'guid'       : owner,
                'data'       : sdata,
            }
            if guid == guids.EfiCertX509:
                sig['x509'] = x509.load_der_x509_certificate(sdata)
                if extract:
                    extract_cert(var, sig['ascii_guid'], sig['x509'])
            sigs.append(sig)
            spos += ssize

        var['siglists'].append({
            'ascii_guid' : guid,
            'guid'       : data[ pos : pos + 16 ],
            'header'     : data[ pos + 16 + 12 : pos + 16 + 12 + hsize ],
            'sigs'       : sigs,
        })
        pos += lsize

def parse_vars(data, start, end, extract):
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
            var['guid'] = data[pos + 44 :
                               pos + 44 + 16]
            var['name'] = data[pos + 44 + 16 :
                               pos + 44 + 16 + nsize]
            var['data'] = data[pos + 44 + 16 + nsize :
                               pos + 44 + 16 + nsize + dsize]

            var['time'] = parse_time(data, pos + 16)
            var['ascii_guid'] = guids.parse(var['guid'], 0)
            var['ascii_name'] = ucs16.from_ucs16(var['name'], 0)
            varlist[var['ascii_name']] = var

            if (var['ascii_name'] == "PK"  or
                var['ascii_name'] == "KEK" or
                var['ascii_name'] == "db"  or
                var['ascii_name'] == "dbx" or
                var['ascii_name'] == "MokList"):
                parse_sigs(var, extract)

        pos = pos + 44 + 16 + nsize + dsize
        pos = (pos + 3) & ~3 # align
    return varlist

def parse_varstore(file, data, start):
    guid = guids.parse(data, start)
    (size, storefmt, state) = struct.unpack_from("=LBB", data, start + 16)
    print(f'varstore={guids.name(guid)} size=0x{size:x} '
          f'format=0x{storefmt:x} state=0x{state:x}')
    if guid != guids.AuthVars:
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
    guid = guids.parse(data, 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
        struct.unpack_from("=QLLHHHxBLL", data, 32)
    print(f'vol={guids.name(guid)} vlen=0x{vlen:x} rev={rev} '
          f'blocks={blocks}*{blksize} (0x{blocks * blksize:x})')
    if sig != 0x4856465f:
        print(f"ERROR: {file}: not a firmware volume")
        sys.exit(1)
    if guid != guids.NvData:
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
    pathoffset = ucs16.get_size(var['data'], 6) + 6
    print(f'    boot entry: name={name} pathoffset=0x{pathoffset:x}')

def print_boot_list(var):
    bootlist = []
    for pos in range(len(var['data']) >> 1):
        nr = struct.unpack_from('=H', var['data'], pos * 2)
        bootlist.append(f'{nr[0]:04d}')
    desc= ", ".join(bootlist)
    print(f'    boot order: {desc}')

def print_ascii(var):
    print(f"    string: {var['data'].decode()}")

def print_siglists(var):
    for item in var['siglists']:
        name = guids.name(item['ascii_guid'])
        count = len(item['sigs'])
        print(f'    list type={name} count={count}')
        cert = item['sigs'][0].get('x509')
        if cert:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
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
    name = var['ascii_name']
    gname = guids.name(var['ascii_guid'])
    size = len(var['data'])
    print(f'  - name={name} guid={gname} size={size}')
    pfunc = print_funcs.get(var['ascii_name'])
    if pfunc:
        pfunc(var)
    if var.get('siglists'):
        print_siglists(var)
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

def update_data_from_siglists(var):
    siglists = var.get('siglists')
    if not siglists:
        return
    blob = b''
    for siglist in siglists:
        sigs = b''
        count = 0
        for sig in siglist['sigs']:
            sigs += sig['guid']
            sigs += sig['data']
            count += 1
        blob += siglist['guid']
        blob += struct.pack("=LLL",
                            16 + 12 + len(siglist['header']) + len(sigs),
                            len(siglist['header']),
                            int(len(sigs) / count))
        blob += siglist['header']
        blob += sigs
    var['data'] = blob

def write_time(time):
    blob = struct.pack("=HBBBBBxLhBx",
                       time['year'], time['month'], time['day'],
                       time['hour'], time['min'], time['sec'],
                       time['ns'], time['tz'], time['dl'])
    return blob

def write_var(var):
    blob = struct.pack("=HBxLQ",
                       0x55aa, 0x3f,
                       var['attr'],
                       var['count'])
    blob += write_time(var['time'])
    blob += struct.pack("=LLL",
                        var['pkidx'],
                        len(var['name']),
                        len(var['data']))
    blob += var['guid']
    blob += var['name']
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
    now = datetime.datetime.now(datetime.timezone.utc)
    var['time']['year']  = now.year
    var['time']['month'] = now.month
    var['time']['day']   = now.day
    var['time']['hour']  = now.hour
    var['time']['min']   = now.minute
    var['time']['sec']   = now.second

def var_create(varlist, name):
    cfg = vars_settings.get(name)
    if not cfg:
        print(f'ERROR: unknown variable {name}')
        sys.exit(1)

    print(f'# create variable {name}')
    var = var_template.copy()
    var['ascii_guid'] = cfg['guid']
    var['ascii_name'] = name
    var['guid']       = guids.binary(cfg['guid'])
    var['name']       = ucs16.to_ucs16(name)
    var['attr']       = cfg['attr']
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

def var_add_cert(varlist, name, owner, file, replace = False):
    var = varlist.get(name)
    if not var:
        var = var_create(varlist, name)
    if not var.get('siglists') or replace:
        print(f'# init/clear {name} siglist')
        var['siglists'] = []

    print(f'# add {name} cert {file}')
    with open(file, "rb") as f:
        pem = f.read()
    if b'-----BEGIN' in pem:
        cert = x509.load_pem_x509_certificate(pem)
    else:
        cert = x509.load_der_x509_certificate(pem)
    certdata = cert.public_bytes(serialization.Encoding.DER)
    for c in var['siglists']:
        if c['sigs'][0]['data'] == certdata:
            print('# certificate already present, skipping')
            return
    sigs = []
    sigs.append({
        'ascii_guid' : owner,
        'guid'       : guids.binary(owner),
        'data'       : certdata,
        'x509'       : cert,
    })
    var['siglists'].append({
        'ascii_guid' : guids.EfiCertX509,
        'guid'       : guids.binary(guids.EfiCertX509),
        'header'     : b'',
        'sigs'       : sigs,
    })
    update_data_from_siglists(var)
    var_update_time(var)


def var_add_dummy_dbx(varlist, owner):
    var = varlist.get('dbx')
    if var:
        return

    var = var_create(varlist, 'dbx')
    var['siglists'] = []

    print("# add dummy dbx entry")
    sigs = []
    sigs.append({
        'ascii_guid' : owner,
        'guid'       : guids.binary(owner),
        'data'       : hashlib.sha256(b'').digest(),
    })
    var['siglists'].append({
        'ascii_guid' : guids.EfiCertSha256,
        'guid'       : guids.binary(guids.EfiCertSha256),
        'header'     : b'',
        'sigs'       : sigs,
    })
    update_data_from_siglists(var)
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

    print(f'"# reading varstore from {options.input}')
    with open(options.input, "rb") as f:
        infile = f.read()

    (start, end) = parse_volume(options.input, infile)
    print(f'var store range: 0x{start:x} -> 0x{end:x}')
    varlist = parse_vars(infile, start, end, options.extract)

    if options.delete:
        vars_delete(varlist, options.delete)

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
