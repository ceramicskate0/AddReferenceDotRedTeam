using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AddReferenceDotRedTeam
{
    public static class Function
    {
        public static string GeneratePassword()
        {
            const string space = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var builder = new StringBuilder();
            var random = new Random();
            for (var i = 0; i < 12; i++)
            {
                builder.Append(space[random.Next(space.Length)]);
            }
            return builder.ToString();
        }

        public static bool ValidateRemoteCertificate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            if (error == System.Net.Security.SslPolicyErrors.None)
            {
                return true;
            }
            Console.WriteLine("X509Certificate [{0}] Policy Error: '{1}'",
                cert.Subject,
                error.ToString());
            return false;
        }

    }
}
