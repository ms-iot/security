Import-Module $PSScriptRoot\IoTDeviceGuardSecureBoot.psm1 -Force
Import-Module $PSScriptRoot\IoTDeviceGuardBitLocker.psm1 -Force
Import-Module $PSScriptRoot\IoTDeviceGuardSIPolicy.psm1 -Force
Import-Module $PSScriptRoot\IoTDeviceGuardOEMCustomization.psm1 -Force

$ErrorActionPreference = 'stop'

function New-IotDeviceGuardPackage([string]$ConfigFileName)
{
    New-IoTSecureBootPackage -ConfigFileName $ConfigFileName
    New-IoTBitLockerPackage -ConfigFileName $ConfigFileName
    New-IoTSIPolicyPackage -ConfigFileName $ConfigFileName
    New-IoTOEMCustomizationPackage -ConfigFileName $ConfigFileName
}

Export-ModuleMember -Function New-IotDeviceGuardPackage
