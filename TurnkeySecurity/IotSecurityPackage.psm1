Import-Module $PSScriptRoot\IoTSecureBoot.psm1 -Force
Import-Module $PSScriptRoot\IoTBitLocker.psm1 -Force
Import-Module $PSScriptRoot\IoTSIPolicy.psm1 -Force
Import-Module $PSScriptRoot\IoTOEMCustomization.psm1 -Force
Import-Module $PSScriptRoot\IoTUtils.psm1 -Force

$ErrorActionPreference = 'stop'

function New-IotSecurityPackage([string]$ConfigFileName)
{
    DownloadProductionWindowsCert -ConfigFileName $ConfigFileName
    New-IoTSecureBootPackage -ConfigFileName $ConfigFileName
    New-IoTBitLockerPackage -ConfigFileName $ConfigFileName
    New-IoTSIPolicyPackage -ConfigFileName $ConfigFileName
    New-IoTOEMCustomizationPackage -ConfigFileName $ConfigFileName
}

Export-ModuleMember -Function New-IotSecurityPackage
