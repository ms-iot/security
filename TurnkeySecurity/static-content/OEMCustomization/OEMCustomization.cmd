:: OEM Customization Script File

if exist c:\IoTSec\setup.secureboot.cmd  (
    call c:\IoTSec\setup.secureboot.cmd
)

if exist c:\IoTSec\setup.bitlocker.cmd  (
    call c:\IoTSec\setup.bitlocker.cmd
)
