param([string]$OemName="OEM", [string] $outputPath)

$ErrorActionPreference = 'stop'

function CreateDirectoryIfNotExist([string]$path)
{
    if (-not (Test-Path $path))
    {
        return (New-Item -Path $path -ItemType Directory)
    }
    return (Get-Item -path $path)
}

$ToolsDir="C:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x86\"
$MakeCert=$ToolsDir+"makecert.exe"
$pvkpfx=$ToolsDir+"pvk2pfx.exe"
$SignTool=$ToolsDir+"signtool.exe"

$outputDir = (CreateDirectoryIfNotExist -path $outputPath).FullName
$pfxOutputDir = (CreateDirectoryIfNotExist -path "$outputPath\private").FullName

# Filenames
$Root = "$outputDir\$OemName-Root"
$RootPfx = "$pfxOutputDir\$OemName-Root"
$CA = "$outputDir\$OemName-CA"
$CAPfx = "$pfxOutputDir\$OemName-CA"
$PCA = "$outputDir\$OemName-PCA"
$PCAPfx = "$pfxOutputDir\$OemName-PCA"
$PK = "$outputDir\$OemName-pk"
$PKPfx = "$pfxOutputDir\$OemName-pk"
$KEK = "$outputDir\$OemName-UEFISB"
$KEKPfx = "$PfxOutputDir\$OemName-UEFISB"
$SIPolicySigner = "$outputDir\$OemName-PAUTH"
$SIPolicySignerPfx = "$PfxOutputDir\$OemName-PAUTH"
$UMCI = "$outputDir\$OemName-UMCI"
$UMCIPfx = "$PfxOutputDir\$OemName-UMCI"
$BitlockerDRA = "$outputDir\$OemName-DRA"
$BitlockerDRAPfx = "$PfxOutputDir\$OemName-DRA"

$ReApply = Test-Path "$Root.pfx"
If($ReApply -eq $False){
& $MakeCert -r -pe -n "CN=$OemName Root" -ss CA -sr CurrentUser -a sha256 -len 4096 -cy authority -sky signature -sv "$Root.pvk" "$Root.cer"
& $pvkpfx -pvk "$root.pvk" -spc "$Root.cer" -pfx "$RootPfx.pfx"
}

$ReApply = Test-Path "$CA.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName CA" -ss CA -sr CurrentUser -a sha256 -len 4096 -cy authority -sky signature -iv "$Root.pvk" -ic "$Root.cer" -sv "$CA.pvk" "$CA.cer"
& $pvkpfx -pvk "$CA.pvk" -spc "$CA.cer" -pfx "$CAPfx.pfx"
& Remove-Item "$root.pvk"
}

$ReApply = Test-Path "$PCA.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName Production PCA 2016" -ss CA -sr CurrentUser -a sha256 -len 4096 -cy authority -sky signature -iv "$CA.pvk" -ic "$CA.cer" -sv "$PCA.pvk" "$PCA.cer"
& $pvkpfx -pvk "$PCA.pvk" -spc "$PCA.cer" -pfx "$PCAPfx.pfx"
& Remove-Item "$CA.pvk"
}

$ReApply = Test-Path "$SIPolicySigner.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName Lockdown Policy Authority, E=Info@$OemName-Name.com" -sr CurrentUser -a sha256 -len 2048 -cy end -sky signature -iv "$PCA.pvk" -ic "$PCA.cer" -sv "$SIPolicySigner.pvk" "$SIPolicySigner.cer"
& $pvkpfx -pvk "$SIPolicySigner.pvk" -spc "$SIPolicySigner.cer" -pfx "$SIPolicySignerPfx.pfx"
& Remove-Item "$SIPolicySigner.pvk"
}

$ReApply = Test-Path "$UMCI.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName UMCI Codesigning, E=Info@$OemName-Name.com" -sr CurrentUser -a sha256 -len 2048 -cy end -eku 1.3.6.1.5.5.7.3.3 -sky signature -iv "$PCA.pvk" -ic "$PCA.cer" -sv "$UMCI.pvk" "$UMCI.cer"
& $pvkpfx -pvk "$UMCI.pvk" -spc "$UMCI.cer" -pfx "$UMCIPfx.pfx"
& Remove-Item "$UMCI.pvk"

}

$ReApply = Test-Path "$PK.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName Platform Key" -sr CurrentUser -a sha256 -len 2048 -cy end -sky signature -iv "$PCA.pvk" -ic "$PCA.cer" -sv "$PK.pvk"  "$PK.cer"
& $pvkpfx -pvk "$PK.pvk" -spc "$PK.cer" -pfx "$PKPfx.pfx"
& Remove-Item "$PK.pvk"
}

$ReApply = Test-Path "$KEK.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName Secure Boot" -sr CurrentUser -a sha256 -len 2048 -cy end -sky signature -iv "$PCA.pvk" -ic "$PCA.cer" -sv "$KEK.pvk"  "$KEK.cer"
& $pvkpfx -pvk "$KEK.pvk" -spc "$KEK.cer" -pfx "$KEKPfx.pfx"
& Remove-Item "$KEK.pvk"
}

$ReApply = Test-Path "$BitlockerDRA.pfx"
If($ReApply -eq $False){
& $MakeCert -pe -n "CN=$OemName Data Recovery Agent" -sr CurrentUser -a sha256 -len 2048 -cy end -eku 1.3.6.1.4.1.311.67.1.2 -sky exchange -iv "$PCA.pvk" -ic "$PCA.cer" -sv "$BitlockerDRA.pvk" "$BitlockerDRA.cer"
& $pvkpfx -pvk "$BitlockerDRA.pvk" -spc "$BitlockerDRA.cer" -pfx "$BitlockerDRAPfx.pfx"
& Remove-Item "$PCA.pvk"
& Remove-Item "$BitlockerDRA.pvk"
}