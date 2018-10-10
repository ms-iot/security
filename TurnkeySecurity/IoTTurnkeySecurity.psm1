﻿Import-Module $PSScriptRoot\IoTSecureBoot.psm1 -Force
Import-Module $PSScriptRoot\IoTBitLocker.psm1 -Force
Import-Module $PSScriptRoot\IoTSIPolicy.psm1 -Force
Import-Module $PSScriptRoot\IoTOEMCustomization.psm1 -Force
Import-Module $PSScriptRoot\IoTUtils.psm1 -Force

$ErrorActionPreference = 'stop'

function New-IoTTurnkeySecurity([string]$ConfigFileName, [switch]$Test)
{
    New-IoTSecureBootPackage -ConfigFileName $ConfigFileName $Test
    New-IoTBitLockerPackage -ConfigFileName $ConfigFileName
    New-IoTSIPolicyPackage -ConfigFileName $ConfigFileName $Test
    New-IoTOEMCustomizationPackage -ConfigFileName $ConfigFileName
}

Export-ModuleMember -Function New-IoTTurnkeySecurity
