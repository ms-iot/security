#Requires -RunAsAdministrator

$ErrorActionPreference = 'stop'

Import-Module $PSScriptRoot\IoTDeviceGuardUtils.psm1 -Force

function Get-BitLockerOutputDirectory([xml] $config)
{
    $OutputDir = CreateDirectoryIfNotExist -path "$($Config.Settings.General.OutputDirectory)\BitLocker"
    return $OutputDir
}

function GenerateBitlockerDataRecoveryAgentPackageXml([xml] $config)
{
    $OutputDir = Get-BitLockerOutputDirectory -config $config
    
    $dra = (Get-Item -path $config.Settings.BitLocker.DataRecoveryAgent)
    $thumbprint = (Get-PfxCertificate -FilePath $dra).Thumbprint

    # Convert the certificate into registry format.
    # Import the cert into a cert store.  Get blob from registry.  Delete the cert from cert store.
    try
    {
        Import-Certificate -FilePath $dra -CertStoreLocation Cert:\LocalMachine\My
        $blob = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\$thumbprint).Blob

        # convert 'blob' from array to 'int' to a comma delimited string of hex values
        $blob = (($blob | foreach {$_.ToString("x2") }) -join ',')
    }
    finally
    {
        Remove-Item -Path Cert:\LocalMachine\My\$thumbprint
    }

    # load the template
    $packageXml = get-item -path $OutputDir\DeviceGuard.Bitlocker.pkg.xml
    $content =  Get-Content -path $packageXml
      
    # replace the placeholder with actual values and write back the file
    $content = $content -replace "{_DRA_THUMBPRINT_}", $thumbprint
    $content = $content -replace "{_DRA_CERT_BLOB_}", $blob
    Set-Content -path $packageXml -Value $content
}

<# 
 .Synopsis
  Generate a new package for enabling BitLocker.

 .Description
  Generate a new package for enabling BitLocker.

 .Parameter ConfigFileName
  Path to config file.  The following values are used:

    Settings.BitLocker.DataRecoveryAgent
        File path to the key used to unlock the drive during a BitLocker recovery scenario.

    Settings.Packaging.OemName
        Name of the OEM

    Settings.Packaging.Architecture
        Architecture of the device

    Settings.Packaging.BspVersion
        BSP version

    Settings.Packaging.SignToolOEMSign (optional)
        Optional setting for signing the generated packages

 .Example
   New-IotBitLockerPacage -configFileName "settings.xml"
#>
function New-IoTBitLockerPackage([string] $ConfigFileName)
{
    $ConfigFile = Get-Item -Path $ConfigFileName
    [xml] $config = Get-Content -Path $ConfigFile
    
    # Change current directory to the config file Since all file paths are relative to the config file.
    Push-Location -path $ConfigFile.directory

    try
    {
        $OutputDir = Get-BitLockerOutputDirectory -config $config

        Copy-Item -Path "$PSScriptRoot\static-content\BitLocker\*.*" -Destination $outputDir
        GenerateBitlockerDataRecoveryAgentPackageXml -config $config
        MakeCabSingle -config $config -PackageXml (get-item -path "$OutputDir\DeviceGuard.BitLocker.pkg.xml")
    }
    finally
    {
        Pop-Location 
    }
}

Export-ModuleMember -Function New-IoTBitLockerPackage
