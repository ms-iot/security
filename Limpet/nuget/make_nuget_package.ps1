# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

function GetAssemblyVersionFromFile($filename) {
    $regex = 'AssemblyVersion\("(\d{1,3}\.\d{1,3}\.\d{1,3}).*"\)'
    $values = select-string -Path $filename -Pattern $regex | % { $_.Matches } | % { $_.Groups } | % { $_.Value }
    if( $values.Count -eq 2 ) {
        return $values[1]
    }
    Write-Host "Error: Unable to find AssemblyVersion in $filename" -foregroundcolor "red"
    exit
}

if (-Not (Test-Path 'NuGet.exe')) {
    Invoke-WebRequest 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' -OutFile 'NuGet.exe' 
}

# Delete existing packages to force rebuild
ls Microsoft.Devices.Tpm.*.nupkg | % { del $_ }

# Get the assembly versions from both files, make sure they match, and use that as the package version
$dotNetFile = "..\Limpet.NET\Properties\AssemblyInfo.cs"
$winRTNetFile = "..\Limpet.UWP\Properties\AssemblyInfo.cs"

$v1 = GetAssemblyVersionFromFile($dotNetFile)
$v2 = GetAssemblyVersionFromFile($winRTNetFile)

if($v1 -ne $v2) {
    Write-Host "Error: Mismatching assembly versions in files $dotNetFile and $winRTNetFile. Check AssemblyVersion attribute in each file." -foregroundcolor "red"
    return
}

$id='Microsoft.Devices.Tpm'

$file1="..\Limpet.NET\bin\Release\Microsoft.Devices.Tpm.dll"
$file2="..\Limpet.UWP\bin\Release\Microsoft.Devices.Tpm.dll"

echo "Creating NuGet package $id version $v1..."
echo "Using files:"
echo "$file1 for .NET"
echo "$file2 for UWP"

.\NuGet.exe pack "$id.nuspec" -Prop Configuration=Release -Prop id=$id -Prop Version=$v1 -Prop file1=$file1 -Prop file2=$file2
