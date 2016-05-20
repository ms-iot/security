using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Devices.Tpm;

namespace LimpetTest
{
    class Program
    {
        static void Main(string[] args)
        {
            TpmDevice myLimpet = new TpmDevice(0);
            string hwDeviceID = myLimpet.GetHardwareDeviceId();
        }
    }
}
