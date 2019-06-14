:: Setup bitlocker

reg query HKLM\Software\IoT /v DeviceGuardBitlockerSetup >nul 2>&1

if %errorlevel% == 1 (
    schtasks /Create /TN "\Microsoft\Windows\IoT\DeviceEncryption" /XML %~dp0DETask.xml /f
    reg add HKLM\Software\IoT /v DeviceGuardBitlockerSetup /t REG_DWORD /d 1 /f >nul 2>&1
    goto :end
)

REM :: Enable below scripts to wait until the bit locker encryption completed on the device.
REM reg query HKLM\Software\IoT /v DeviceGuardBitlockerEncryptionComplete >nul 2>&1

REM if %errorlevel% == 0 ( goto :end )

REM echo.	>>%systemdrive%\bitlockerstatus.log 2>&1
REM echo Waiting for bit locker encryption to complete....	>>%systemdrive%\bitlockerstatus.log 2>&1
REM echo started @ %DATE% %TIME%	>>%systemdrive%\bitlockerstatus.log 2>&1
REM %windir%\system32\sectask.exe -waitencryptcomplete:1800	>nul 2>&1

REM if %errorlevel% == 0 (
REM 	reg add HKLM\Software\IoT /v DeviceGuardBitlockerEncryptionComplete /t REG_DWORD /d 1 /f >nul 2>&1
REM 	echo Device bit locker encryption completed successfully.	>>%systemdrive%\bitlockerstatus.log 2>&1
REM 	echo ended @ %DATE% %TIME%	>>%systemdrive%\bitlockerstatus.log 2>&1
REM     goto :end )

REM if %errorlevel% == -2147023436 (
REM 	echo Device bit locker encryption timed out.	>>%systemdrive%\bitlockerstatus.log 2>&1
REM     goto :end )

REM echo Error %errorlevel% occurred in bit locker encryption.	>>%systemdrive%\bitlockerstatus.log 2>&1

:end