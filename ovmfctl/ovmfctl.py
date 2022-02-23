#!/usr/bin/python
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

###############################################################################################################
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


###############################################################################################################
# parse stuff

def parse_guid(data, offset):
    guid = uuid.UUID(bytes_le = data[offset:offset+16])
    name = guid.urn.split(":")[2]
    return name

def parse_unicode(data, offset):
    pos = offset
    ascii = ""
    while True:
        unichar = struct.unpack_from("=H", data, pos)
        if unichar[0] == 0:
            break
        if unichar[0] >= 128:
            ascii += "?"
        else:
            ascii += "%c" % unichar[0]
        pos += 2
    return ascii

def parse_time(data, offset):
    (year, month, day, hour, min, sec, ns, tz, dl) = struct.unpack_from("=HBBBBBxLhBx", data, offset)
    time = {
        'year'  : year,
        'month' : month,
        'day'   : day,
        'hour'  : hour,
        'min'   : min,
        'sec'   : sec,
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
        print("# WARNNG: exists: %s" % filename)
        return
    print("# writing " + filename)
    file = open(filename, "wb")
    file.write(cert.public_bytes(serialization.Encoding.PEM))
    file.close()

def parse_sigs(var, extract):
    data = var['data']
    pos = 0
    var['siglists'] = []
    while pos < len(data):
        guid = parse_guid(data, pos)
        (lsize, hsize, ssize) = struct.unpack_from("=LLL", data, pos + 16)
        dpos = pos + 16 + 12 + hsize
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
    vars = {}
    while pos < end:
        (id, state, attr, count) = struct.unpack_from("=HBxLQ", data, pos)
        if id != 0x55aa:
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
            vars[var['ascii_name']] = var

            if (var['ascii_name'] == "PK"  or
                var['ascii_name'] == "KEK" or
                var['ascii_name'] == "db"  or
                var['ascii_name'] == "dbx" or
                var['ascii_name'] == "MokList"):
                parse_sigs(var, extract)

        pos = pos + 44 + 16 + nsize + dsize
        pos = (pos + 3) & ~3; # align
    return vars
    
def parse_varstore(file, data, start):
    guid = parse_guid(data, start)
    (size, format, state) = struct.unpack_from("=LBB", data, start + 16)
    print("varstore=%s size=0x%x format=0x%x state=0x%x" %
          (guids.name(guid), size, format, state))
    if guid != guids.AuthVars:
        print(f"ERROR: {file}: unknown varstore guid")
        exit(1)
    if format != 0x5a:
        print(f"ERROR: {file}: unknown varstore format")
        exit(1)
    if state != 0xfe:
        print(f"ERROR: {file}: unknown varstore state")
        exit(1)
    return (start + 16 + 12, start + size)

def parse_volume(file, data):
    guid = parse_guid(data, 16)
    (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = struct.unpack_from("=QLLHHHxBLL", data, 32)
    print("vol=%s vlen=0x%x rev=%d blocks=%dx%d (0x%x)" %
          (guids.name(guid), vlen, rev, blocks, blksize, blocks * blksize))
    if sig != 0x4856465f:
        print(f"ERROR: {file}: not a firmware volume")
        exit(1)
    if guid != guids.NvData:
        print(f"ERROR: {file}: not a variable store")
        exit(1)
    return parse_varstore(file, data, hlen)


###############################################################################################################
# print stuff, debug logging

def print_hexdump(data, start, end):
    hex = ""
    ascii = ""
    pos = start
    count = 0
    while True:
        hex += "%02x " % data[start+count]
        if (data[start+count] > 0x20 and
            data[start+count] < 0x7f):
            ascii += "%c" % data[start+count]
        else:
            ascii += "."
        count += 1
        if count % 4 == 0:
            hex += " "
            ascii += " "
        if count % 16 == 0 or start+count == end:
            print("    %06x: %-52s %s" % (pos, hex, ascii))
            hex = ""
            ascii = ""
            pos += 16
        if count == 256 or start+count == end:
            break
    if start+count < end:
        print("    %06x: [ ... ]" % (pos))

def print_null(var):
    return

def print_bool(var):
    if (var['data'][0]):
        print("    bool ON")
    else:
        print("    bool off")

def print_ascii(var):
    print("    string %s" % var['data'].decode())

def print_siglists(var):
    for item in var['siglists']:
        print("    list type=%s count=%d" % (guids.name(item['ascii_guid']),
                                             len(item['sigs'])))
        cert = item['sigs'][0].get('x509')
        if cert:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
            print("      x509 CN=%s" % cn.value)

print_funcs = {
    'SecureBootEnable' : print_bool,
    'CustomMode'       : print_bool,

    'Lang'             : print_ascii,
    'PlatformLang'     : print_ascii,
}

def print_var(var, verbose, hexdump):
    print("  - name=%s guid=%s size=%d" %
          (var['ascii_name'], guids.name(var['ascii_guid']), len(var['data'])))
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

def print_vars(vars, verbose, hexdump):
    print("# printing variables ...")
    for item in vars.keys():
        print_var(vars[item], verbose, hexdump)
    print("# ... done")


###############################################################################################################
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

def vars_delete(vars, delete):
    for item in delete:
        if vars.get(item):
            print("# delete variable: %s" % item)
            del vars[item]
        else:
            print("# WARNING: variable %s not found" % item)

def var_guid(ascii):
    guid = uuid.UUID('urn:uuid:' + ascii)
    return guid.bytes_le

def var_name(ascii):
    unicode = b''
    for char in list(ascii):
        unicode += char.encode()
        unicode += b'\x00'
    unicode += b'\x00\x00'
    return unicode

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

def var_create(vars, name):
    cfg = vars_settings.get(name)
    if not cfg:
        print("ERROR: unknown variable %s" % name)
        exit(1)

    print("# create variable %s" % name)
    var = var_template.copy()
    var['ascii_guid'] = cfg['guid']
    var['ascii_name'] = name
    var['guid']       = var_guid(cfg['guid'])
    var['name']       = var_name(name)
    var['attr']       = cfg['attr']
    vars[name] = var
    return var

def var_set_bool(vars, name, value):
    var = vars.get(name)
    if not var:
        var = var_create(vars, name)

    if value:
        var['data'] = b'\x01'
    else:
        var['data'] = b'\x00'
    var_update_time(var)

def var_add_cert(vars, name, owner, file, replace = False):
    var = vars.get(name)
    if not var:
        var = var_create(vars, name)
    if not var.get('siglists') or replace:
        print("# init/clear %s siglist" % name)
        var['siglists'] = []

    print("# add %s cert %s" % (name, file))
    file = open(file, "rb");
    pem = file.read()
    file.close()
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


def var_add_dummy_dbx(vars, owner):
    var = vars.get('dbx')
    if var:
        return

    var = var_create(vars, 'dbx')
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


###############################################################################################################
# main

def main():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', dest = 'input', type = 'string',
                      help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_option('--extract-certs', dest = 'extract', action = 'store_true', default = False,
                      help = 'extract all certificates')
    parser.add_option('-d', '--delete', dest = 'delete', action = 'append', type = 'string',
                      help = 'delete variable VAR, can be specified multiple times', metavar = 'VAR')
    parser.add_option('--set-pk', dest = 'pk',  nargs = 2,
                      help = 'set PK to x509 cert, loaded in pem format from FILE and with owner GUID',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-kek', dest = 'kek',  action = 'append', nargs = 2,
                      help = 'add x509 cert to KEK, loaded in pem format from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--add-db', dest = 'db',  action = 'append', nargs = 2,
                      help = 'add x509 cert to db, loaded in pem format from FILE and with owner GUID, can be specified multiple times',
                      metavar = ('GUID', 'FILE'))
    parser.add_option('--sb', '--secure-boot', dest = 'secureboot',  action = 'store_true', default = False,
                      help = 'enable secure boot mode')
    parser.add_option('-p', '--print', dest = 'print', action = 'store_true', default = False,
                      help = 'print varstore')
    parser.add_option('-v', '--verbose', dest = 'verbose', action = 'store_true', default = False,
                      help = 'print varstore verbosely')
    parser.add_option('-x', '--hexdump', dest = 'hexdump', action = 'store_true', default = False,
                      help = 'print variable hexdumps')
    parser.add_option('-o', '--output', dest = 'output', type = 'string',
                      help = 'write edk2 vars to FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    if not options.input:
        print("ERROR: no input file specified (try -h for help)")
        exit(1)

    print("# reading varstore from %s" % options.input)
    file = open(options.input, "rb");
    infile = file.read()
    file.close()

    (start, end) = parse_volume(options.input, infile)
    print("var store range: 0x%x -> 0x%x" % (start, end))
    vars = parse_vars(infile, start, end, options.extract)

    if options.delete:
        vars_delete(vars, options.delete)

    if options.pk:
        var_add_cert(vars, 'PK', options.pk[0], options.pk[1], True)

    if options.kek:
        for item in options.kek:
            var_add_cert(vars, 'KEK', item[0], item[1])

    if options.db:
        for item in options.db:
            var_add_cert(vars, 'db', item[0], item[1])

    if options.secureboot:
        var_add_dummy_dbx(vars, "a0baa8a3-041d-48a8-bc87-c36d121b5e3d")
        var_set_bool(vars, 'SecureBootEnable', True)
        var_set_bool(vars, 'CustomMode', False)

    if options.print:
        print_vars(vars, options.verbose, options.hexdump)

    if options.output:
        outfile = infile[:start]
        for item in vars.keys():
            outfile += write_var(vars[item])

        if len(outfile) > end:
            print("ERROR: varstore is too small")
            exit(1)

        outfile += b''.zfill(end - len(outfile))
        outfile += infile[end:]
        
        print("# writing varstore to %s" % options.output)
        file = open(options.output, "wb");
        file.write(outfile)
        file.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
