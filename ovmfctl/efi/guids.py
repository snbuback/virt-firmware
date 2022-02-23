#!/usr/bin/python

NvData         = "fff12b8d-7696-4c8b-a985-2747075b4f50"
AuthVars       = "aaf32c78-947b-439a-a180-2e144ec37792"

EfiCertX509    = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EfiCertSha256  = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

name_table = {
    # firmware volumes
    NvData                                 : "NvData",
    AuthVars                               : "AuthVars",

    # variable types
    "8be4df61-93ca-11d2-aa0d-00e098032b8c" : "EfiGlobalVariable",
    "d719b2cb-3d3a-4596-a3bc-dad00e67656f" : "EfiImageSecurityDatabase",
    "eb704011-1402-11d3-8e77-00a0c969723b" : "MtcVendor",
    "c076ec0c-7028-4399-a072-71ee5c448b9f" : "EfiCustomModeEnable",
    "f0a30bc7-af08-4556-99c4-001009c93a44" : "EfiSecureBootEnableDisable",
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
}

def name(guid):
    name = name_table.get(guid, None)
    if name is None:
        return guid
    return "guid:%s" % name
