using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;
using AddReferenceDotRedTeam;

namespace Out_CompressedDll
{
    class Out_CompressedDll
    {

        public static string Out_Compressed_Dll(string Path , string TemplatePath="")
        {

            if (!File.Exists(Path))
            {
                throw new System.ArgumentException(Path + " does not exist.");
            }

            byte[] FileBytes = File.ReadAllBytes(Path);

            if (FileBytes.Length < 1)
            {
                throw new System.ArgumentException(Path + "is not a valid executable.");
            }

            return Convert.ToBase64String(Function.Compress(FileBytes));
        }
    }
}
