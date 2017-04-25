#Requires -RunAsAdministrator

$ErrorActionPreference = 'stop'

Import-Module $PSScriptRoot\IoTDeviceGuardUtils.psm1 -Force

function Get-SIPolicyOutputDirectory([xml] $config)
{
    $OutputDir = CreateDirectoryIfNotExist -path "$($Config.Settings.General.OutputDirectory)\DeviceGuard"
    return $OutputDir
}

function GenerateInitialSIPolicy([xml] $config)
{
    Write-host "GenerateInitialSIPolicy ...."

    $IntDir = GetIntermediateDirectory -config $config

    $scanPath = $config.Settings.SIPolicy.ScanPath
    if (-not $scanPath)
    {
        throw "No ScanPath specified."
    }

    if (-not (Test-path -path $scanPath))
    {
        throw "Invalid ScanPath specified."
    }

    $initialPolicy = "$IntDir\InitialScan.xml"
    Write-Host "Scanning $scanPath ...."
    $DeviceOsVolume = $scanPath
    New-CIPolicy -Level PcaCertificate -FilePath $initialPolicy -fallback Hash -ScanPath "$DeviceOsVolume" -PathToCatroot "$DeviceOsVolume\Windows\System32\catroot" -UserPEs 3> "$IntDir\CIPolicyLog.txt"
    return $initialPolicy
}

function GenerateSIPolicy([xml] $config)
{
    Write-host "GenerateSIPolicy ...."

    $OutputDir = Get-SIPolicyOutputDirectory -config $config
    $IntDir = GetIntermediateDirectory -config $config

    # Get tools
    $signtool = GetSignToolFromConfig($config)

    $initialPolicy = $config.Settings.SIPolicy.InitialPolicy
    if (-not $initialPolicy)
    {
        $initialPolicy = GenerateInitialSIPolicy -config $config
    }

    Write-host "Using Initial Policy: $initialPolicy ...."

    # Policy filenames
    $auditPolicy = "$IntDir\AuditPolicy.xml"
    $auditPolicyBin = "$IntDir\AuditPolicy.bin"
    $auditPolicyP7b = "$OutputDir\SIPolicyOff.p7b"
    $enforcedPolicy = "$IntDir\EnforcedPolicy.xml"
    $enforcedPolicyBin = "$IntDir\enforcedPolicy.bin"
    $enforcedPolicyP7b = "$OutputDir\SIPolicyOn.p7b"

    Copy-Item -Path $initialPolicy -Destination $auditPolicy -Force
    
    # Use the first update key to sign
    $updatePfx = ($Config.Settings.SIPolicy.Update.PFX | Select-Object -first 1 | Get-Item ).FullName

    # Add 'update' certs
    $updateCerts = ($Config.Settings.SIPolicy.Update.Cert | Get-Item).FullName
    foreach ($cert in $updateCerts)
    {
        Add-SignerRule -CertificatePath $cert -FilePath $auditPolicy -update
    }

    # Add 'user' certs
    $userCerts = ($Config.Settings.SIPolicy.User.Cert | Get-Item).FullName
    foreach ($cert in $userCerts)
    {
        Add-SignerRule -CertificatePath $cert -FilePath $auditPolicy -user
    }

    # Add 'kernel' certs
    $kernelCerts = ($Config.Settings.SIPolicy.Kernel.Cert | Get-Item).FullName
    foreach ($cert in $kernelCerts)
    {
        Add-SignerRule -CertificatePath $cert -FilePath $auditPolicy -kernel
    }

    ConvertFrom-CIPolicy -XmlFilePath $auditPolicy -BinaryFilePath $auditPolicyBin
    & $SignTool sign -v /f $updatePfx /p7 $IntDir /p7co 1.3.6.1.4.1.311.79.1 /fd sha256 $auditPolicyBin
    Copy-Item -Path "$auditPolicyBin.p7" -Destination $auditPolicyP7b

    Copy-Item -Path $auditPolicy -Destination $enforcedPolicy -Force
    # Disable Audit Mode
    Set-RuleOption -FilePath $enforcedPolicy -Option 3 -Delete
    # Disable Unsigned System Integrity Policy
    Set-RuleOption -FilePath $enforcedPolicy -Option 6 -Delete
    # Disable Advanced Boot Options Menu
    Set-RuleOption -FilePath $enforcedPolicy -Option 9 -Delete

    ConvertFrom-CIPolicy -XmlFilePath $enforcedPolicy -BinaryFilePath $enforcedPolicyBin
    & $SignTool sign -v /f $updatePfx /p7 $IntDir /p7co 1.3.6.1.4.1.311.79.1 /fd sha256 $enforcedPolicyBin
    Copy-Item -Path "$enforcedPolicyBin.p7" -Destination $enforcedPolicyP7b
}

<# 
 .Synopsis
  Generate a new package for enabling SIPolicy.

 .Description
  Generate a new package for enabling SIPolicy.

 .Parameter ConfigFileName
  Path to config file.  The following values are used:

    Settings.SIPolicy.ScanPath
        File path to your golden device image.

    Settings.SIPolicy.Update.PFX
        File path to the private key used to sign SIPolicy.

    Settings.SIPolicy.Update.Cert
        File paths to list of the public keys that can sign and update the SIPolicy.

    Settings.SIPolicy.Kernel.Cert
        File paths to list of the public keys that can sign kernel mode components.

    Settings.SIPolicy.User.Cert
        File paths to list of the public keys that can sign user mode components.

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
function New-IoTSIPolicyPackage([string] $ConfigFileName)
{
    $ConfigFile = Get-Item -Path $ConfigFileName
    [xml] $config = Get-Content -Path $ConfigFile
    
    # Change current directory to the config file Since all file paths are relative to the config file.
    Push-Location -path $ConfigFile.directory

    try
    {
        $OutputDir = Get-SIPolicyOutputDirectory -config $config

        Copy-Item -Path "$PSScriptRoot\static-content\DeviceGuard\*.*" -Destination $outputDir
        GenerateSIPolicy $config
        MakeCabSingle -config $config -PackageXml (get-item -path "$OutputDir\Security.DeviceGuard.pkg.xml")
    }
    finally
    {
        Pop-Location 
    }
}
