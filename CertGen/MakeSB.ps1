Import-Module secureboot

#==RootCert==#
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\MakeCert.exe' -r -cy authority -len 4096 -m 120 -a sha256 -sv SecureBootRoot.pvk -pe -ss my -n "CN=SecureBootRoot" SecureBootRoot.cer
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\pvk2pfx.exe' -pvk SecureBootRoot.pvk -spc SecureBootRoot.cer -pfx SecureBootRoot.pfx -f

#==CACert==#
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\MakeCert.exe' -cy authority -len 2048 -m 60 -a sha256 -ic SecureBootRoot.cer -iv SecureBootRoot.pvk -sv SecureBootCA.pvk -pe -ss my -n "CN=SecureBootCA" SecureBootCA.cer
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\pvk2pfx.exe' -pvk SecureBootCA.pvk -spc SecureBootCA.cer -pfx SecureBootCA.pfx -f

#==SecureBootCert==#
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\MakeCert.exe' -len 2048 -m 12 -a sha256 -ic SecureBootCA.cer -iv SecureBootCA.pvk -sv SecureBoot.pvk -pe -ss my -n "CN=SecureBoot" SecureBoot.cer
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\pvk2pfx.exe' -pvk SecureBoot.pvk -spc SecureBoot.cer -pfx SecureBoot.pfx -f

#==PlatformKeyCert==#
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\MakeCert.exe' -len 2048 -m 12 -a sha256 -ic SecureBootCA.cer -iv SecureBootCA.pvk -sv SecureBootPK.pvk -pe -ss my -n "CN=SecureBootPK" SecureBootPK.cer
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\pvk2pfx.exe' -pvk SecureBootPK.pvk -spc SecureBootPK.cer -pfx SecureBootPK.pfx -f

#==CustomCodesigningCert==#
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\MakeCert.exe' -len 2048 -m 12 -a sha256 -ic SecureBootCA.cer -iv SecureBootCA.pvk -sv CodeSigning.pvk -pe -ss my -n "CN=CodeSigning" -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.8 CodeSigning.cer
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\pvk2pfx.exe' -pvk CodeSigning.pvk -spc CodeSigning.cer -pfx CodeSigning.pfx -f

#==Selfsigned DRACert==#
write-output '[NewRequest]' >dra.inf
write-output 'Subject = "CN=PFXBitLockerDRA"' >>dra.inf
write-output 'Exportable = true' >>dra.inf                  # Remove this if DRA protector is TPM or SmartCard bound
write-output 'KeyLength = 2048' >>dra.inf
#ProviderName = "Microsoft Platform Crypto Provider"        # Device bound TPM protected private key (can not be exported)
#ProviderName = "Microsoft Smart Card Key Storage Provider" # SmartCard bound TPM protected private key (can not be exported)
write-output 'KeySpec = "AT_KEYEXCHANGE"' >>dra.inf
write-output 'KeyUsage = "CERT_KEY_ENCIPHERMENT_KEY_USAGE"' >>dra.inf
write-output 'KeyUsageProperty = "NCRYPT_ALLOW_DECRYPT_FLAG"' >>dra.inf
write-output 'RequestType = Cert' >>dra.inf
write-output 'SMIME = FALSE' >>dra.inf
write-output '[EnhancedKeyUsageExtension]' >>dra.inf
write-output 'OID=1.3.6.1.4.1.311.67.1.2' >>dra.inf
& certreq -new .\dra.inf BitLockerDRA.cer
Remove-Item dra.inf

#==DB==#
Format-SecureBootUEFI -Name db -SignatureOwner 77fa9abd-0359-4d32-bd60-28f4e78f784b -ContentFilePath signing_signatures_SigList.bin -FormatWithCert -CertificateFilePath db\db_MSFTproductionWindowsSigningCA2011.cer,db\db_MSFTproductionUEFIsigningCA.cer,db\db_MSFTpreReleaseCandidateWindowsSigningCA.cer,db\db_MSFTtestSigningRoot.cer,db\db_MSFTUEFILogoTestSigner.cer,CodeSigning.cer -SignableFilePath signing_signatures_SigList_Serialization.bin -Time 2015-08-31T00:00:00Z -AppendWrite: $false
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe' sign /fd sha256 /p7 .\ /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /u "1.3.6.1.4.1.311.79.2.1" /f SecureBoot.pfx signing_signatures_SigList_Serialization.bin
Set-SecureBootUEFI -Name db -Time 2015-08-31T00:00:00Z -ContentFilePath signing_signatures_SigList.bin -SignedFilePath signing_signatures_SigList_Serialization.bin.p7 -OutputFilePath SetVariable_db.bin

#==KEK==#
Format-SecureBootUEFI -Name KEK -SignatureOwner 00000000-0000-0000-0000-000000000000 -ContentFilePath CA_SigList.bin -FormatWithCert -CertificateFilePath SecureBootCA.cer -SignableFilePath CA_SigList_Serialization.bin -Time 2015-08-31T00:00:00Z -AppendWrite: $false
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe' sign /fd sha256 /p7 .\ /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /f SecureBootPK.pfx CA_SigList_Serialization.bin
Set-SecureBootUEFI -Name KEK -Time 2015-08-31T00:00:00Z -ContentFilePath CA_SigList.bin -SignedFilePath CA_SigList_Serialization.bin.p7 -OutputFilePath SetVariable_kek.bin

#==PK==#
Format-SecureBootUEFI -Name PK -SignatureOwner 55555555-5555-5555-5555-555555555555 -ContentFilePath PlatformKey_SigList.bin -FormatWithCert -CertificateFilePath SecureBootPK.cer -SignableFilePath PlatformKey_SigList_Serialization.bin -Time 2015-08-31T00:00:00Z -AppendWrite: $false
& 'C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe' sign /fd sha256 /p7 .\ /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /f SecureBootPK.pfx PlatformKey_SigList_Serialization.bin
Set-SecureBootUEFI -Name PK -Time 2015-08-31T00:00:00Z -ContentFilePath PlatformKey_SigList.bin -SignedFilePath PlatformKey_SigList_Serialization.bin.p7 -OutputFilePath SetVariable_pk.bin

#==BitLockerDRAStore==#
& reg delete HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE /f
& certutil –f -GroupPolicy -addstore FVE BitLockerDRA.cer
& reg export HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE DRAStore.reg
& reg delete HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE /f
$regfile = Get-Content .\DRAStore.reg
$regfile = $regfile.replace('\SOFTWARE\', '\IoT\')
$regfile = $regfile + '[HKEY_LOCAL_MACHINE\IoT\Policies\Microsoft\FVE]'
$regfile = $regfile + '"OSManageDRA"=dword:00000001'
$regfile = $regfile + '"FDVManageDRA"=dword:00000001'
$regfile = $regfile + '"RDVManageDRA"=dword:00000001'
$regfile = $regfile + '"IdentificationField"=dword:00000001'
$regfile = $regfile + '"IdentificationFieldString"="BitLocker"'
$regfile = $regfile + '"SecondaryIdentificationField"="BitLocker"'
$regfile = $regfile + '"SelfSignedCertificates"=dword:00000001'
$regfile = $regfile + '"RDVDeviceBinding"=dword:00000001'
$regfile = $regfile + '"OSEnablePrebootInputProtectorsOnSlates"=dword:00000001'
Set-Content .\DRAStore.reg $regfile
