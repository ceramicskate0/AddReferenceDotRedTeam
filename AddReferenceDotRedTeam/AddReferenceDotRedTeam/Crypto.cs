using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AddReferenceDotRedTeam
{
    public static class Crypto
    {
        /// <summary>
        /// Ecrypt data in memory.
        /// </summary>
        /// <param name="plainText">Not encrypted contents</param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns>Ecrypted contents</returns>
        public static byte[] Encrypt_MemoryContents(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        /// <summary>
        /// Decrypt data in memory.
        /// </summary>
        /// <param name="cipherText">Encrypted conetents</param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns>Decrypted contents</returns>
        public static string Decrypt_MemoryContents(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        /// <summary>
        /// Generates a Hash value of any listed hash algo in Ref URL.
        /// REF:https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm.create?view=netframework-4.8#System_Security_Cryptography_HashAlgorithm_Create_System_String_
        /// </summary>
        /// <param name="Data"></param>
        /// <param name="Hash_Algo"></param>
        /// <param name="SALT"></param>
        /// <returns>Hash ouput</returns>
        public static string Hash(string Data, string Hash_Algo, string SALT="")
        {
            byte[] bytes = Encoding.Unicode.GetBytes(Data);
            byte[] src = Encoding.Unicode.GetBytes(SALT);
            byte[] dst = new byte[src.Length + bytes.Length];
            Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            Buffer.BlockCopy(bytes, 0, dst, src.Length, bytes.Length);
            HashAlgorithm algorithm = HashAlgorithm.Create(Hash_Algo);
            if (algorithm != null)
            {
                byte[] inArray = algorithm.ComputeHash(dst);
                var encodedPassword = Convert.ToBase64String(inArray);
                return encodedPassword;
            }
            return Data;
        }

    }
}
