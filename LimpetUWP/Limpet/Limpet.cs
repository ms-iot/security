using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Limpet
{
    public class LimpetDevice
    {
        private const UInt32 AIOTH_PERSISTED_URI_INDEX = 0x01400100;
        private const UInt32 AIOTH_PERSISTED_KEY_HANDLE = 0x81000100;
        private const UInt32 SRK_HANDLE = 0x81000001;

        UInt32 logicalDeviceId = 0;
        public LimpetDevice(UInt32 logicalDeviceId)
        {
            this.logicalDeviceId = logicalDeviceId;
        }

        public LimpetDevice(string DeviceIdName)
        {
            for(logicalDeviceId = 0; logicalDeviceId < 10; logicalDeviceId++)
            {
                if(GetDeviceId().CompareTo(DeviceIdName) == 0)
                {
                    break;
                }
            }
            if(logicalDeviceId > 9)
            {
                throw new IndexOutOfRangeException();
            }
        }

        public string GetHardwareDeviceId()
        {
            TpmHandle srkHandle = new TpmHandle(SRK_HANDLE);
            string hardwareDeviceId = "";
            Byte[] name;
            Byte[] qualifiedName;

            try
            {
                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                var tpm = new Tpm2(tpmDevice);

                // Read the URI from the TPM
                TpmPublic srk = tpm.ReadPublic(srkHandle, out name, out qualifiedName);

                // Dispose of the TPM
                tpm.Dispose();
            }
            catch
            {
                return hardwareDeviceId;
            }

            // Calculate the hardware device id for this logical device
            byte[] deviceId = CryptoLib.HashData(TpmAlgId.Sha256, BitConverter.GetBytes(logicalDeviceId), name);

            // Produce the output string
            foreach (byte n in deviceId)
            {
                hardwareDeviceId += n.ToString("x2");
            }
            return hardwareDeviceId;
        }

        public void Provision(string encodedHmacKey, string hostName, string deviceId = "")
        {
            TpmHandle nvHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);
            TpmHandle srkHandle = new TpmHandle(SRK_HANDLE);
            UTF8Encoding utf8 = new UTF8Encoding();
            byte[] nvData = utf8.GetBytes(hostName + "/" + deviceId);
            byte[] hmacKey = System.Convert.FromBase64String(encodedHmacKey);

            // Open the TPM
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            var tpm = new Tpm2(tpmDevice);

            // Define the store
            tpm.NvDefineSpace(ownerHandle,
                              new byte[0],
                              new NvPublic(nvHandle,
                                           TpmAlgId.Sha256,
                                           NvAttr.Authwrite | NvAttr.Authread | NvAttr.NoDa,
                                           new byte[0],
                                           (ushort)nvData.Length));

            // Write the store
            tpm.NvWrite(nvHandle, nvHandle, nvData, 0);

            // Import the HMAC key under the SRK
            TpmPublic hmacPub;
            CreationData creationData;
            byte[] creationhash;
            TkCreation ticket;
            TpmPrivate hmacPrv = tpm.Create(srkHandle,
                                            new SensitiveCreate(new byte[0],
                                                                hmacKey),
                                            new TpmPublic(TpmAlgId.Sha256,
                                                          ObjectAttr.UserWithAuth | ObjectAttr.NoDA | ObjectAttr.Sign,
                                                          new byte[0],
                                                          new KeyedhashParms(new SchemeHmac(TpmAlgId.Sha256)),
                                                          new Tpm2bDigestKeyedhash()),
                                            new byte[0],
                                            new PcrSelection[0],
                                            out hmacPub,
                                            out creationData,
                                            out creationhash,
                                            out ticket);

            // Load the HMAC key into the TPM
            TpmHandle loadedHmacKey = tpm.Load(srkHandle, hmacPrv, hmacPub);

            // Persist the key in NV
            tpm.EvictControl(ownerHandle, loadedHmacKey, hmacKeyHandle);

            // Unload the transient copy from the TPM
            tpm.FlushContext(loadedHmacKey);
        }

        public void Destroy()
        {
            TpmHandle nvHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);

            // Open the TPM
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            var tpm = new Tpm2(tpmDevice);

            // Destyroy the URI
            tpm.NvUndefineSpace(ownerHandle, nvHandle);

            // Destroy the HMAC key
            tpm.EvictControl(ownerHandle, hmacKeyHandle, hmacKeyHandle);

            // Dispose of the TPM
            tpm.Dispose();
        }

        private string GetHeldData()
        {
            TpmHandle nvUriHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);
            Byte[] nvData;
            string iotHubUri = "";

            try
            {
                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                var tpm = new Tpm2(tpmDevice);

                // Read the URI from the TPM
                Byte[] name;
                NvPublic nvPublic = tpm.NvReadPublic(nvUriHandle, out name);
                nvData = tpm.NvRead(nvUriHandle, nvUriHandle, nvPublic.dataSize, 0);

                // Dispose of the TPM
                tpm.Dispose();
            }
            catch
            {
                return iotHubUri;
            }

            // Convert the data to a srting for output
            iotHubUri = System.Text.Encoding.UTF8.GetString(nvData);
            return iotHubUri;
        }

        public string GetDeviceId()
        {
            string rawTpmData = GetHeldData();
            int separator = rawTpmData.IndexOf('/') + 1;
            if(rawTpmData.Length > separator)
            {
                return rawTpmData.Substring(separator);
            }
            else
            {
                return GetHardwareDeviceId();
            }
        }

        public string GetHostName()
        {
            string rawTpmData = GetHeldData();
            int separator = rawTpmData.IndexOf('/');
            if (separator > 0)
            {
                return rawTpmData.Substring(0, separator);
            }
            else
            {
                return "";
            }
        }

        public Byte[] SignHmac(Byte[] dataToSign)
        {
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);
            int dataIndex = 0;
            Byte[] iterationBuffer;
            Byte[] hmac = { };

            if (dataToSign.Length <= 1024)
            {
                try
                {
                    // Open the TPM
                    Tpm2Device tpmDevice = new TbsDevice();
                    tpmDevice.Connect();
                    var tpm = new Tpm2(tpmDevice);

                    // Calculate the HMAC in one shot
                    hmac = tpm.Hmac(hmacKeyHandle, dataToSign, TpmAlgId.Sha256);

                    // Dispose of the TPM
                    tpm.Dispose();
                }
                catch
                {
                    return hmac;
                }
            }
            else
            {
                try
                {
                    // Open the TPM
                    Tpm2Device tpmDevice = new TbsDevice();
                    tpmDevice.Connect();
                    var tpm = new Tpm2(tpmDevice);

                    // Start the HMAC sequence
                    Byte[] hmacAuth = new byte[0];
                    TpmHandle hmacHandle = tpm.HmacStart(hmacKeyHandle, hmacAuth, TpmAlgId.Sha256);
                    while (dataToSign.Length > dataIndex + 1024)
                    {
                        // Repeat to update the hmac until we only hace <=1024 bytes left
                        iterationBuffer = new Byte[1024];
                        Array.Copy(dataToSign, dataIndex, iterationBuffer, 0, 1024);
                        tpm.SequenceUpdate(hmacHandle, iterationBuffer);
                        dataIndex += 1024;
                    }
                    // Finalize the hmac with the remainder of the data
                    iterationBuffer = new Byte[dataToSign.Length - dataIndex];
                    Array.Copy(dataToSign, dataIndex, iterationBuffer, 0, dataToSign.Length - dataIndex);
                    TkHashcheck nullChk;
                    hmac = tpm.SequenceComplete(hmacHandle, iterationBuffer, TpmHandle.RhNull, out nullChk);

                    // Dispose of the TPM
                    tpm.Dispose();
                }
                catch
                {
                    return hmac;
                }
            }

            return hmac;
        }

        private string AzureUrlEncode(string stringIn)
        {
            UTF8Encoding utf8 = new UTF8Encoding();
            string[] conversionTable = {
            "\0", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
            "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f",
            "%20", "!", "%22", "%23", "%24", "%25", "%26", "%27", "(", ")", "*", "%2b", "%2c", "-", ".", "%2f",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "%3a", "%3b", "%3c", "%3d", "%3e", "%3f",
            "%40", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "%5b", "%5c", "%5d", "%5e", "_",
            "%60", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "%7b", "%7c", "%7d", "%7e", "%7f",
            "%c2%80", "%c2%81", "%c2%82", "%c2%83", "%c2%84", "%c2%85", "%c2%86", "%c2%87", "%c2%88", "%c2%89", "%c2%8a", "%c2%8b", "%c2%8c", "%c2%8d", "%c2%8e", "%c2%8f",
            "%c2%90", "%c2%91", "%c2%92", "%c2%93", "%c2%94", "%c2%95", "%c2%96", "%c2%97", "%c2%98", "%c2%99", "%c2%9a", "%c2%9b", "%c2%9c", "%c2%9d", "%c2%9e", "%c2%9f",
            "%c2%a0", "%c2%a1", "%c2%a2", "%c2%a3", "%c2%a4", "%c2%a5", "%c2%a6", "%c2%a7", "%c2%a8", "%c2%a9", "%c2%aa", "%c2%ab", "%c2%ac", "%c2%ad", "%c2%ae", "%c2%af",
            "%c2%b0", "%c2%b1", "%c2%b2", "%c2%b3", "%c2%b4", "%c2%b5", "%c2%b6", "%c2%b7", "%c2%b8", "%c2%b9", "%c2%ba", "%c2%bb", "%c2%bc", "%c2%bd", "%c2%be", "%c2%bf",
            "%c3%80", "%c3%81", "%c3%82", "%c3%83", "%c3%84", "%c3%85", "%c3%86", "%c3%87", "%c3%88", "%c3%89", "%c3%8a", "%c3%8b", "%c3%8c", "%c3%8d", "%c3%8e", "%c3%8f",
            "%c3%90", "%c3%91", "%c3%92", "%c3%93", "%c3%94", "%c3%95", "%c3%96", "%c3%97", "%c3%98", "%c3%99", "%c3%9a", "%c3%9b", "%c3%9c", "%c3%9d", "%c3%9e", "%c3%9f",
            "%c3%a0", "%c3%a1", "%c3%a2", "%c3%a3", "%c3%a4", "%c3%a5", "%c3%a6", "%c3%a7", "%c3%a8", "%c3%a9", "%c3%aa", "%c3%ab", "%c3%ac", "%c3%ad", "%c3%ae", "%c3%af",
            "%c3%b0", "%c3%b1", "%c3%b2", "%c3%b3", "%c3%b4", "%c3%b5", "%c3%b6", "%c3%b7", "%c3%b8", "%c3%b9", "%c3%ba", "%c3%bb", "%c3%bc", "%c3%bd", "%c3%be", "%c3%bf" };
            string stringOut = "";
            foreach(char n in stringIn)
            {
                stringOut += conversionTable[n];
            }
            return stringOut;
        }

        public string GetSASToken(uint validity = 3600)
        {
            const long WINDOWS_TICKS_PER_SEC = 10000000;
            const long EPOCH_DIFFERNECE = 11644473600;
            string deviceId = GetDeviceId();
            string hostName = GetHostName();
            long expirationTime = (DateTime.Now.ToUniversalTime().ToFileTime() / WINDOWS_TICKS_PER_SEC) - EPOCH_DIFFERNECE;
            string sasToken = "";
            if ((hostName.Length > 0) && (deviceId.Length > 0))
            {
                // Encode the message to sign with the TPM
                UTF8Encoding utf8 = new UTF8Encoding();
                string tokenContent = hostName + "/devices/" + deviceId + "\n" + expirationTime;
                Byte[] encodedBytes = utf8.GetBytes(tokenContent);

                // Sign the message
                Byte[] hmac = SignHmac(encodedBytes);

                // if we got a signature foramt it
                if (hmac.Length > 0)
                {
                    // Encode the output and assemble the connection string
                    string hmacString = AzureUrlEncode(System.Convert.ToBase64String(hmac));
                    sasToken = "SharedAccessSignature sr=" + hostName + "/devices/" + deviceId + "&sig=" + hmacString + "&se=" + expirationTime;
                }
            }
            return sasToken;
        }

        public string GetConnectionString(uint validity = 3600)
        {
            string deviceId = GetDeviceId();
            string hostName = GetHostName();
            string sasToken = GetSASToken(validity);
            string connectionString = "";
            if ((hostName.Length > 0) && (deviceId.Length > 0) && (sasToken.Length > 0))
            {
                connectionString = "HostName=" + hostName + ";DeviceId=" + deviceId + ";SharedAccessSignature=" + sasToken;
            }
            return connectionString;
        }
    }
}
