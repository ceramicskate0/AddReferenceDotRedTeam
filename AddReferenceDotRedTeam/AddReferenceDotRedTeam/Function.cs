using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Security;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AddReferenceDotRedTeam
{
    public static class Function
    {
        public static string GeneratePassword(int Length=16)
        {
            const string space = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var builder = new StringBuilder();
            var random = new Random();
            for (var i = 0; i < Length; i++)
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

        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        public static byte[] Serialize(object ToSerialize)
        {
            try
            {
                BinaryFormatter serializer = new BinaryFormatter();
                using (var memoryStream = new MemoryStream())
                {
                    serializer.Serialize(memoryStream, ToSerialize);
                    return memoryStream.ToArray();
                }
            }
            catch (Exception e)
            {
                return null;
            }
        }

        public static byte[] DecompressDLL_GZip(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }
    }
}
