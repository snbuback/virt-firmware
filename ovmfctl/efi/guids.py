#!/usr/bin/python
""" efi guid database and helper functions """

import uuid

Ffs                          = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
NvData                       = "fff12b8d-7696-4c8b-a985-2747075b4f50"
AuthVars                     = "aaf32c78-947b-439a-a180-2e144ec37792"
LzmaCompress                 = "ee4e5898-3914-4259-9d6e-dc7bd79403cf"
ResetVector                  = "1ba0062e-c779-4582-8566-336ae8f78f09"

EfiGlobalVariable            = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EfiImageSecurityDatabase     = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EfiSecureBootEnableDisable   = "f0a30bc7-af08-4556-99c4-001009c93a44"
EfiCustomModeEnable          = "c076ec0c-7028-4399-a072-71ee5c448b9f"

EfiCertX509                  = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EfiCertSha256                = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

OvmfGuidList                 = "96b582de-1fb2-45f7-baea-a366c55a082d"
OvmfSevMetadataOffset        = "dc886566-984a-4798-a75e-5585a7bf67cc"
TdxMetadataOffset            = "e47a6535-984a-4798-865e-4685a7bf8ec2"

name_table = {
    # firmware volumes
    Ffs                                    : "Ffs",
    NvData                                 : "NvData",
    AuthVars                               : "AuthVars",
    LzmaCompress                           : "LzmaCompress",
    ResetVector                            : "ResetVector",

    "9e21fd93-9c72-4c15-8c4b-e77f1db2d792" : "FvMainCompact",
    "df1ccef6-f301-4a63-9661-fc6030dcc880" : "SecMain",

    # variable types
    EfiGlobalVariable                      : "EfiGlobalVariable",
    EfiImageSecurityDatabase               : "EfiImageSecurityDatabase",
    EfiSecureBootEnableDisable             : "EfiSecureBootEnableDisable",
    EfiCustomModeEnable                    : "EfiCustomModeEnable",

    "eb704011-1402-11d3-8e77-00a0c969723b" : "MtcVendor",
    "4c19049f-4137-4dd3-9c10-8b97a83ffdfa" : "EfiMemoryTypeInformation",
    "4b47d616-a8d6-4552-9d44-ccad2e0f4cf9" : "IScsiConfig",
    "d9bee56e-75dc-49d9-b4d7-b534210f637a" : "EfiCertDb",

    # protocols (also used for variables)
    "59324945-ec44-4c0d-b1cd-9db139df070c" : "EfiIScsiInitiatorNameProtocol",
    "9fb9a8a1-2f4a-43a6-889c-d0f7b6c47ad5" : "EfiDhcp6ServiceBindingProtocol",
    "937fe521-95ae-4d1a-8929-48bcd90ad31a" : "EfiIp6ConfigProtocol",

    # signature list types
    EfiCertX509                            : "EfiCertX509",
    EfiCertSha256                          : "EfiCertSha256",

    # signature owner
    "77fa9abd-0359-4d32-bd60-28f4e78f784b" : "MicrosoftVendor",
    "a0baa8a3-041d-48a8-bc87-c36d121b5e3d" : "OvmfEnrollDefaultKeys",

    # ovmf metadata
    OvmfGuidList                           : "OvmfGuidList",
    OvmfSevMetadataOffset                  : "OvmfSevMetadataOffset",
    TdxMetadataOffset                      : "TdxMetadataOffset",

    "7255371f-3a3b-4b04-927b-1da6efa8d454" : "SevHashTableBlock",
    "4c2eb361-7d9b-4cc3-8081-127c90d3d294" : "SevSecretBlock",
    "00f771de-1a7e-4fcb-890e-68c77e2fb44e" : "SevProcessorReset",

    # misc
    "ffffffff-ffff-ffff-ffff-ffffffffffff" : "NotValid",
}

def name(guid):
    nstr = name_table.get(guid, None)
    if nstr is None:
        return guid
    return f'guid:{nstr}'

def parse(data, offset):
    guid = uuid.UUID(bytes_le = data[offset:offset+16])
    nstr = guid.urn.split(":")[2]
    return nstr

def binary(nstr):
    guid = uuid.UUID(f'urn:uuid:{nstr}')
    return guid.bytes_le
