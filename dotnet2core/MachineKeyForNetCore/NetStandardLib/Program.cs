using System;
using System.Collections.Generic;
using System.Text;

namespace NetStandardLib
{
    public class Program
    {
        static void Main()
        {
            var purpose = "AA";
            var text = "StoneLi";

            var dataBuffer = Encoding.UTF8.GetBytes(text);

            var coreProtectBuffer = CoreMachineKey.Protect(dataBuffer, purpose);

            var base64String = Convert.ToBase64String(coreProtectBuffer);
            Console.WriteLine(base64String);

            var buffer = Convert.FromBase64String(base64String);

            var coreUnProtectBuffer = CoreMachineKey.UnProtect(buffer, purpose);
            Console.WriteLine(Encoding.UTF8.GetString(coreUnProtectBuffer));

            Console.Read();
        }
    }
}
