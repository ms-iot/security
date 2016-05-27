using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Devices.Tpm;

namespace Limpetize
{
    class Program
    {
        static void Main(string[] args)
        {
            if(args.Length < 2)
            {
                HowTo();
                return;
            }

            // Pick the logical LimpetID
            UInt32 logicalId = System.Convert.ToUInt32(args[0]);
            TpmDevice myLimpet = new TpmDevice(logicalId);

            // Decode the command
            if (args[1].ToUpper().Equals("-H"))
            {
                Console.WriteLine("Limpet[{0}] HWDeviceID = {1}", logicalId, myLimpet.GetHardwareDeviceId());
            }
            else if ((args[1].ToUpper().Equals("-P")) && (args.Length > 4))
            {
                if (args.Length > 4)
                {
                    myLimpet.Provision(args[2], args[3], args[4]);
                }
                else
                {
                    myLimpet.Provision(args[2], args[3]);
                }

                Console.WriteLine("Limpet[{0}] provisioned.", logicalId);
            }
            else if (args[1].ToUpper().Equals("-S"))
            {
                if (args.Length > 2)
                {
                    UInt32 validity = System.Convert.ToUInt32(args[2]);
                    Console.WriteLine(myLimpet.GetSASToken(validity));
                }
                else
                {
                    Console.WriteLine(myLimpet.GetSASToken());
                }
            }
            else if (args[1].ToUpper().Equals("-D"))
            {
                myLimpet.Destroy();
                Console.WriteLine("Limpet[{0}] destroyed.", logicalId);
            }
            else
            {
                HowTo();
                return;
            }
        }
        static void HowTo()
        {
            Console.WriteLine("HWDeviceID: Limpetize.exe [LimpetLogicalID] -h ");
            Console.WriteLine("Provision: Limpetize.exe [LimpetLogicalID] -p [Base64HMACKey] [URL] {Optional:DeviceID}");
            Console.WriteLine("SASToken: Limpetize.exe [LimpetLogicalID] -s {Optional:Validity}");
            Console.WriteLine("Destroy: Limpetize.exe [LimpetLogicalID] -d");
        }
    }
}
