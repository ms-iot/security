$ErrorActionPreference = 'stop'

<#
Common utililty
#>
function GetSignToolFromConfig([xml] $config)
{  
    $Win10KitsRoot = (get-item -path $Config.Settings.Tools.Windows10KitsRoot).FullName
	$Win10SDKVersion = $Config.Settings.Tools.WindowsSDKVersion
    $SignTool=(get-item -path "$Win10KitsRoot\bin\$Win10SDKVersion\x86\signtool.exe").FullName
    return $SignTool
}

function GetpvkpfxFromConfig([xml] $config)
{  
    $Win10KitsRoot = (get-item -path $Config.Settings.Tools.Windows10KitsRoot).FullName
	$Win10SDKVersion = $Config.Settings.Tools.WindowsSDKVersion
    $pvkpfx=(get-item -path "$Win10KitsRoot\bin\$Win10SDKVersion\x86\pvk2pfx.exe").FullName
    return $pvkpfx
}

function CreateDirectoryIfNotExist([string]$path)
{
    if (-not (Test-Path $path))
    {
        return (New-Item -Path $path -ItemType Directory)
    }
    return (Get-Item -path $path)
}

function GetIntermediateDirectory([xml] $config)
{
    $IntDir = CreateDirectoryIfNotExist -path $Config.Settings.General.IntermediateDirectory
    return $IntDir
}

function GetPackageOutputDirectory([xml] $config)
{
    $PackageOutputDir = CreateDirectoryIfNotExist -path $Config.Settings.General.PackageOutputDirectory
    return $PackageOutputDir
}

function MakeCabSingle([xml] $config, $PackageXml)
{
    $arch = $config.Settings.Packaging.architecture
    if ([string]::IsNullOrWhiteSpace($arch))
    {
        throw "Invalid architecture"
    }

    $oemName = $config.Settings.Packaging.OemName
    if ([string]::IsNullOrWhiteSpace($oemName))
    {
        throw "No OemName specified."
    }

    $PackageOutputDir = CreateDirectoryIfNotExist -path $Config.Settings.General.PackageOutputDirectory

    $Win10KitsRoot = (get-item -path $Config.Settings.Tools.Windows10KitsRoot).FullName
    $Win10KitsRootBinPath = "$Win10KitsRoot\Tools\bin\i386"
    $PkgGenCmd = "$Win10KitsRootBinPath\pkggen.exe"
    $PkgConfigXml = "$Win10KitsRootBinPath\pkggen.cfg.xml"
    $ADKEnvCmd = "$Win10KitsRoot\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat"

    # save Env
    $savedEnv = Get-ChildItem Env:

    try
    {
        # Set env variables
        $env:Path= "$Win10KitsRootBinPath;$env:Path"

        if ([string]::IsNullOrWhiteSpace($config.Settings.Packaging.SignToolOEMSign))
        {
            $env:SIGNTOOL_OEM_SIGN=$config.Settings.Packaging.SignToolOEMSign
            $env:SIGN_WITH_TIMESTAMP=1
            $env:SIGN_OEM=1
        }

        # Build the command
        $variables="_RELEASEDIR=$PackageOutputDir;OemName=$oemName"
        $BspVersion = $config.Settings.Packaging.BspVersion
        $cmd = "`"$PkgGenCmd`" `"$($PackageXml.FullName)`" /config:`"$PkgConfigXml`" /output:`"$PackageOutputDir`" /version:$BspVersion /build:fre /cpu:$arch /variables:`"$variables`" /onecore" 
        

        # Execute the command
        Write-Host "Generating packages $PackageXml ...."
        Write-Host $cmd
        
        cmd /c " `"$ADKEnvCmd`" && pushd $($PackageXml.Directory) && $cmd 2`>`&1"
        if ($lastexitcode -ne 0)
        {
            throw "Commmand failed with code: $lastexitcode"
        }
    }
    finally
    {
        #restore env
        Remove-Item Env:*
        $savedEnv | ForEach-Object { Set-Content Env:$($_.Name) $_.Value }
    }
}
