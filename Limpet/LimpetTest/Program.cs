using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Limpet;

namespace LimpetTest
{
    class Program
    {
        static void Main(string[] args)
        {
            LimpetDevice myLimpet = new LimpetDevice(0);
            string hwDeviceID = myLimpet.GetHardwareDeviceId();
        }
    }
}
