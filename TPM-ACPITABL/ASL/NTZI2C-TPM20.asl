//
// Compile with:
//   asl.exe NTZI2C.asl
//
// Merge this device definitition with the TPM2 table:
//   copy /b TPM2Tbl.DAT+TPM2Dev.dat ACPITABL.dat
//
// Copy ACPITABL.dat to %windir%\system32, turn on testsigning, and reboot.
//
// TPM2 Table for SPBTPM
// [000h 0000   4]                    Signature : "TPM2"    [Trusted Platform Module hardware interface table]
// [004h 0004   4]                 Table Length : 00000044
// [008h 0008   1]                     Revision : 03
// [009h 0009   1]                     Checksum : 11
// [00Ah 0010   6]                       Oem ID : "MSFT  "
// [010h 0016   8]                 Oem Table ID : "fTPM    "
// [018h 0024   4]                 Oem Revision : 00000001
// [01Ch 0028   4]              Asl Compiler ID : "DM  "
// [020h 0032   4]        Asl Compiler Revision : 20141014
// [024h 0036   4]                        Flags : 00000000
// [028h 0040   8]              Control Address : 0000000000000000
// [030h 0048   4]                 Start Method : 0000000A
// 
// Content of TPM2Tbl.dat - Raw Table Data: Length 68 (0x44)
// 0000: 54 50 4D 32 44 00 00 00 03 11 4D 53 46 54 20 20  TPM2D.....MSFT  
// 0010: 66 54 50 4D 20 20 20 20 01 00 00 00 44 4D 20 20  fTPM    ....DM  
// 0020: 14 10 14 20 00 00 00 00 00 00 00 00 00 00 00 00  ... ............
// 0030: 0A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
// 0040: 00 00 00 00                                      ....
//

DefinitionBlock ("TPM2Dev.dat", "SSDT", 1, "MSFT", "I2CNTZ", 1)
{
    Scope (\_SB)
    {
        Device(TPM1)
        {
            Name(_HID, "NATZ0101")
            Name(_CID, "MSFT0101")
            Name(_UID, 1)
            Name(_DDN, "NationZ TPM 2.0 Device")            // _DDN: DOS Device Name
            Name(_STR, Unicode ("NationZ TPM 2.0 Device"))  // _STR: Description String
            Name(RBUF, ResourceTemplate ()
            {
// MinnowBoardMax 400KHz
              I2cSerialBus(0x58, ControllerInitiated, 400000, AddressingMode7Bit, "\\_SB.I2C6", 0x00, ResourceConsumer, ,)
// RaspberryPi2 400KHz
//              I2cSerialBus(0x58, ControllerInitiated, 400000, AddressingMode7Bit, "\\_SB.I2C1", 0x00, ResourceConsumer, ,)
            })
            Method(_CRS, 0x0, NotSerialized)
            {
                Return(RBUF)
            }
        }
    }
}