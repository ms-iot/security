#Requires -RunAsAdministrator

$ErrorActionPreference = 'stop'

Import-Module $PSScriptRoot\IoTDeviceGuardUtils.psm1 -Force

function Get-OEMCustomizationOutputDirectory([xml] $config)
{
    $OutputDir = CreateDirectoryIfNotExist -path "$($Config.Settings.General.OutputDirectory)\OEMCustomization"
    return $OutputDir
}

function New-IoTOEMCustomizationPackage([string] $ConfigFileName)
{
    $ConfigFile = Get-Item -Path $ConfigFileName
    [xml] $config = Get-Content -Path $ConfigFile
    
    # Change current directory to the config file Since all file paths are relative to the config file.
    Push-Location -path $ConfigFile.directory

    try
    {
        $OutputDir = Get-OEMCustomizationOutputDirectory -config $config

        Copy-Item -Path "$PSScriptRoot\static-content\OEMCustomization\*.*" -Destination $outputDir
        MakeCabSingle -config $config -PackageXml (get-item -path "$OutputDir\Custom.Cmd.pkg.xml ")
    }
    finally
    {
        Pop-Location 
    }
}

Export-ModuleMember -Function New-IoTOEMCustomizationPackage
