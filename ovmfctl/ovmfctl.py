#!/usr/bin/python
""" print and edit ovmf varstore files """
import os
import sys
import uuid
import struct
import pprint
import hashlib
import optparse
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ovmfctl.efi import guids

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

def parse_guid(data, offset):
    guid = uuid.UUID(bytes_le = data[offset:offset+16])
    name = guid.urn.split(":")[2]
    return name

def parse_unicode(data, offset):
    pos = offset
    name = ""
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        if unichar[0] == 0:
            break
        if unichar[0] >= 128:
            name += "?"
        else:
            name += f'{unichar[0]:c}'
        pos += 2
    return name

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
        guid = parse_guid(data, pos)
        (lsize, hsize, ssize) = struct.unpack_from("=LLL", data, pos + 16)
        siglist = data[ pos + 16 + 12 + hsize : pos+lsize ]
        sigs = []
        spos = 0
        while spos < len(siglist):
            owner = siglist[ spos : spos + 16 ]
            sdata = siglist[ spos + 16 : spos + ssize ]
            sig = {
                'ascii_guid' : parse_guid(owner, 0),
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
            var['ascii_guid'] = parse_guid(var['guid'], 0)
            var['ascii_name'] = parse_unicode(var['name'], 0)
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
    guid = parse_guid(data, start)
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
    guid = parse_guid(data, 16)
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
            print(f'    {pos:06x}: {hstr:52s} {astr}')
            hstr = ''
            astr = ''
            pos += 16
        if count == 256 or start+count == end:
            break
    if start+count < end:
        print(f'    {pos:06x}: [ ... ]')

def print_null(var):
    return

def print_bool(var):
    if var['data'][0]:
        print("    bool: ON")
    else:
        print("    bool: off")

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
}

def print_var(var, verbose, hexdump):
    name = var['ascii_name']
    gname = guids.name(var['ascii_guid'])
    size = len(var['data'])
    print(f'  - name={name} guid={gname} size={size}')
    func = print_funcs.get(var['ascii_name'], print_null)
    func(var)
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
    for item in varlist.keys():
        print_var(varlist[item], verbose, hexdump)
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

def var_guid(name):
    guid = uuid.UUID(f'urn:uuid:{name}')
    return guid.bytes_le

def var_name(astr):
    ustr = b''
    for char in list(astr):
        ustr += char.encode()
        ustr += b'\x00'
    ustr += b'\x00\x00'
    return ustr

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
    var['guid']       = var_guid(cfg['guid'])
    var['name']       = var_name(name)
    var['attr']       = cfg['attr']
    varlist[name] = var
    return var

def var_set_bool(varlist, name, value):
    var = varlist.get(name)
    if not var:
        var = var_create(varlist, name)

    if value:
        var['data'] = b'\x01'
    else:
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
    cert = x509.load_pem_x509_certificate(pem)
    sigs = []
    sigs.append({
        'ascii_guid' : owner,
        'guid'       : var_guid(owner),
        'data'       : cert.public_bytes(serialization.Encoding.DER),
        'x509'       : cert,
    })
    var['siglists'].append({
        'ascii_guid' : guids.EfiCertX509,
        'guid'       : var_guid(guids.EfiCertX509),
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
        'guid'       : var_guid(owner),
        'data'       : hashlib.sha256(b'').digest(),
    })
    var['siglists'].append({
        'ascii_guid' : guids.EfiCertSha256,
        'guid'       : var_guid(guids.EfiCertSha256),
        'header'     : b'',
        'sigs'       : sigs,
    })
    update_data_from_siglists(var)
    var_update_time(var)


##################################################################################################
# main

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

    if options.pk:
        var_add_cert(varlist, 'PK', options.pk[0], options.pk[1], True)

    if options.kek:
        for item in options.kek:
            var_add_cert(varlist, 'KEK', item[0], item[1])

    if options.db:
        for item in options.db:
            var_add_cert(varlist, 'db', item[0], item[1])

    if options.secureboot:
        var_add_dummy_dbx(varlist, "a0baa8a3-041d-48a8-bc87-c36d121b5e3d")
        var_set_bool(varlist, 'SecureBootEnable', True)
        var_set_bool(varlist, 'CustomMode', False)

    if options.print:
        print_vars(varlist, options.verbose, options.hexdump)

    if options.output:
        outfile = infile[:start]
        for item in varlist.keys():
            outfile += write_var(varlist[item])

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
