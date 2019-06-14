:: Setup bitlocker

reg query HKLM\Software\IoT /v DeviceGuardBitlockerSetup >nul 2>&1

if %errorlevel% == 1 (
    schtasks /Create /TN "\Microsoft\Windows\IoT\DeviceEncryption" /XML %~dp0DETask.xml /f
    reg add HKLM\Software\IoT /v DeviceGuardBitlockerSetup /t REG_DWORD /d 1 /f >nul 2>&1
    goto :end
)

:: Enable below scripts to wait until the bit locker encryption completed on the device.
reg query HKLM\Software\IoT /v DeviceGuardBitlockerEncryptionComplete >nul 2>&1

if %errorlevel% == 0 ( goto :end )

echo.	>>%systemdrive%\bitlockerstatus.log 2>&1
echo Waiting for bit locker encryption to complete....	>>%systemdrive%\bitlockerstatus.log 2>&1
echo started @ %DATE% %TIME%	>>%systemdrive%\bitlockerstatus.log 2>&1
%windir%\system32\sectask.exe -waitencryptcomplete:1800	>nul 2>&1

if %errorlevel% == 0 (
	reg add HKLM\Software\IoT /v DeviceGuardBitlockerEncryptionComplete /t REG_DWORD /d 1 /f >nul 2>&1
	echo Device bit locker encryption completed successfully.	>>%systemdrive%\bitlockerstatus.log 2>&1
	echo ended @ %DATE% %TIME%	>>%systemdrive%\bitlockerstatus.log 2>&1
    goto :end )

if %errorlevel% == -2147023436 (
	echo Device bit locker encryption timed out.	>>%systemdrive%\bitlockerstatus.log 2>&1
    goto :end )

echo Error %errorlevel% occurred in bit locker encryption.	>>%systemdrive%\bitlockerstatus.log 2>&1

:end