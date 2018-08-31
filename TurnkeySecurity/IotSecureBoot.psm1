#Requires -RunAsAdministrator

$ErrorActionPreference = 'stop'

Import-Module $PSScriptRoot\IoTUtils.psm1 -Force

<#
Secure boot functions
#>

function Get-SecureBootOutputDirectory([xml] $config)
{
    $OutputDir = CreateDirectoryIfNotExist -path "$($Config.Settings.General.OutputDirectory)\SecureBoot"
    return $OutputDir
}

function GenerateSecureBootFiles([xml] $config, [Boolean] $Test)
{
    # Get tools and commmon directories
    $signtool = GetSignToolFromConfig -config $config
    $OutputDir = Get-SecureBootOutputDirectory -config $config
    $IntDir = GetIntermediateDirectory -config $config
    if( $Test ) { $policySuffix = "_test"; }
    else { $policySuffix = ""; }

    # Resolve the various cert/pfx to full path
    $pkpfx = (Get-Item $Config.Settings.SecureBoot.PlatformKey.PFX).FullName
    $pkcert = (Get-Item $Config.Settings.SecureBoot.PlatformKey.Cert).FullName

    $kekpfx = (Get-Item $Config.Settings.SecureBoot.KeyExchangeKey.PFX).FullName
    $kekcert = ($Config.Settings.SecureBoot.KeyExchangeKey.Cert|Get-Item|Select-Object -Property FullName).FullName

    $db = ($Config.Settings.SecureBoot.Database.Retail.Cert|Get-Item|Select-Object -Property FullName).FullName
    if ($Test) {
        $db += ($Config.Settings.SecureBoot.Database.Test.Cert|Get-Item|Select-Object -Property FullName).FullName
    }
    
    Import-Module secureboot
    # Get current time in format "yyyy-MM-ddTHH':'mm':'ss'Z'"
    $time = (Get-date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # DB
    $objectFromFormat = (Format-SecureBootUEFI -Name db -SignatureOwner 77fa9abd-0359-4d32-bd60-28f4e78f784b -FormatWithCert -CertificateFilePath $db -SignableFilePath "$IntDir\db.bin" -Time $time -AppendWrite: $false)
    & $SignTool sign /fd sha256 /p7 $IntDir /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /u "1.3.6.1.4.1.311.79.2.1" /f "$kekpfx" "$IntDir\db.bin"
    $objectFromFormat | Set-SecureBootUEFI -SignedFilePath "$IntDir\db.bin.p7" -OutputFilePath "$OutputDir\SetVariable_db$policySuffix.bin" | Out-Null

    # KEK
    $objectFromFormat = (Format-SecureBootUEFI -Name KEK -SignatureOwner 00000000-0000-0000-0000-000000000000 -FormatWithCert -CertificateFilePath $kekcert -SignableFilePath "$IntDir\kek.bin" -Time $time -AppendWrite: $false)
    & $SignTool sign /fd sha256 /p7 $IntDir /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /f "$pkpfx" "$IntDir\kek.bin"
    $objectFromFormat | Set-SecureBootUEFI -SignedFilePath "$IntDir\kek.bin.p7" -OutputFilePath "$OutputDir\SetVariable_kek$policySuffix.bin" | Out-Null

    # PK
    $objectFromFormat = (Format-SecureBootUEFI -Name PK -SignatureOwner 55555555-5555-5555-5555-555555555555 -FormatWithCert -CertificateFilePath $pkcert -SignableFilePath "$IntDir\pk.bin" -Time $time -AppendWrite: $false)
    & $SignTool sign /fd sha256 /p7 $IntDir /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /f "$pkpfx" "$IntDir\pk.bin"
    $objectFromFormat | Set-SecureBootUEFI -SignedFilePath "$IntDir\pk.bin.p7" -OutputFilePath "$OutputDir\SetVariable_pk$policySuffix.bin" | Out-Null
}

<# 
 .Synopsis
  Generate a new package for enabling SecureBoot.

 .Description
  Generate a new package for enabling SecureBoot.

 .Parameter ConfigFileName
  Path to config file.  The following values are used:

    Settings.SecureBoot.PlatformKey.PFX
        File path to the private key of the platform key.

    Settings.SecureBoot.PlatformKey.Cert
        File path to the public key of the platform key.

    Settings.SecureBoot.KeyExchangeKey.PFX
        File path to the private key of the KEK.

    Settings.SecureBoot.KeyExchangeKey.Cert
        File paths to the list of approved signers that can update the SecureBoot database.

    Settings.SecureBoot.Database.Cert
        File paths to the list of approved signers for Secure boot Allowed Signature database.
        The contents of the EFI _IMAGE_SECURITY_DATABASE db control what images are trusted 
        when verifying loaded images. 

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
function New-IoTSecureBootPackage([string] $ConfigFileName, [Boolean] $Test)
{
    $ConfigFile = Get-Item -Path $ConfigFileName
    [xml] $config = Get-Content -Path $ConfigFile
    if( $Test ) { $policySuffix = "Test"; }
    else { $policySuffix = ""; }
    
    # Change current directory to the config file Since all file paths are relative to the config file.
    Push-Location -path $ConfigFile.directory

    try
    {
        $OutputDir = Get-SecureBootOutputDirectory -config $config

        Copy-Item -Path "$PSScriptRoot\static-content\SecureBoot\*.*" -Destination $outputDir
        GenerateSecureBootFiles -config $config $Test
        MakeCabSingle -config $config -PackageXml (get-item -path "$OutputDir\Security.SecureBoot$policySuffix.wm.xml")
    }
    finally
    {
        Pop-Location 
    }
}

Export-ModuleMember -Function New-IoTSecureBootPackage
