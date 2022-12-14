#!/usr/bin/python
""" calculate efi variable measurements -- EXPERIMENTAL """
import sys
import json
import hashlib
import logging
import optparse
import collections

from virt.firmware import dump
from virt.firmware.efi import guids
from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2


########################################################################
# measure vars

def measure_var(var):
    namelen = len(var.name.data) >> 1
    datalen = len(var.data)

    varlog = b''
    varlog += var.guid.bytes_le
    varlog += namelen.to_bytes(8, byteorder = 'little')
    varlog += datalen.to_bytes(8, byteorder = 'little')
    varlog += var.name.data
    varlog += var.data

    # modeled after tpm2_eventlog output
    result = {
        'PCRIndex'   : 7,
        'EventType'  : 'EV_EFI_VARIABLE_DRIVER_CONFIG',
        'Digests'    : {
            'sha256' : hashlib.sha256(varlog).hexdigest(),
        },
        'Event' : {
            'VariableName'       : str(var.guid),
            'UnicodeNameLength'  : namelen,
            'VariableDataLength' : datalen,
            'UnicodeName'        : str(var.name),
        },
    }
    return result

def measure_varlist(varlist):
    result = []
    for name in ('PK', 'KEK', 'db', 'dbx'):
        var = varlist.get(name)
        if var:
            result.append(measure_var(var))
    return result


########################################################################
# measure code

def find_volume(item, nameguid = None, typeguid = None):
    if isinstance(item, dump.Edk2Volume):
        if nameguid and item.name and str(item.name) == nameguid:
            return item
        if typeguid and item.guid and str(item.guid) == typeguid:
            return item
    if isinstance(item, collections.UserList):
        for i in list(item):
            r = find_volume(i, nameguid, typeguid)
            if r:
                return r
    return None

def measure_volume(name, vol):
    # modeled after tpm2_eventlog output
    result = {
        'PCRIndex'   : 0,
        'EventType'  : 'EV_EFI_PLATFORM_FIRMWARE_BLOB',
        'VolumeName' : name,
        'Digests'    : {
            'sha256' : vol.sha256.hexdigest()
        },
        'Event' : {
            'BlobLength': vol.tlen,
        },
    }
    return result

def measure_image(image):
    result = []
    peifv = find_volume(image, nameguid = guids.OvmfPeiFv)
    dxefv = find_volume(image, nameguid = guids.OvmfDxeFv)
    vars  = find_volume(image, typeguid = guids.NvData)
    if peifv:
        result.append(measure_volume('PEIFV', peifv))
    if dxefv:
        result.append(measure_volume('DXEFV', dxefv))
    if vars:
        edk2store = edk2.Edk2VarStore(image.name)
        varlist = edk2store.get_varlist()
        result += measure_varlist(varlist)
    return result


########################################################################
# main

def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'info',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_option('--image', dest = 'image', type = 'string',
                      help = 'read edk2 image from FILE', metavar = 'FILE')
    parser.add_option('--vars', dest = 'vars', type = 'string',
                      help = 'read edk2 vars from FILE', metavar = 'FILE')
    (options, args) = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    if options.image:
        with open(options.image, 'rb') as f:
            data = f.read()
        image = dump.Edk2Image(options.image, data)
        result = measure_image(image)
        print(json.dumps(result, indent = 4))

    elif options.vars:
        if edk2.Edk2VarStore.probe(options.vars):
            edk2store = edk2.Edk2VarStore(options.vars)
            varlist = edk2store.get_varlist()
        elif aws.AwsVarStore.probe(options.vars):
            awsstore = aws.AwsVarStore(options.vars)
            varlist = awsstore.get_varlist()
        else:
            logging.error("unknown input file format")
            return 1
        result = measure_varlist(varlist)
        print(json.dumps(result, indent = 4))

    return 0

if __name__ == '__main__':
    sys.exit(main())
