using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace EncryptionAndEncodingHelper
{
    public class EncryptionAndEncoding
    {
        private static TripleDESCryptoServiceProvider encrypter = new TripleDESCryptoServiceProvider();
       //Constructor
        public EncryptionAndEncoding(string Key, string IV)
        {
            //Add the Key, InitializationVector, the KeySize, the cypher mode and the padding to the encryptor object
            encrypter.Key = Encoding.UTF8.GetBytes(Key);
            encrypter.IV = Encoding.UTF8.GetBytes(IV);
            encrypter.Padding = PaddingMode.ISO10126;
        }

        public String EncryptAndEncodeText(string Data)
        {
            try
            {
                // Create a MemoryStream.
                MemoryStream mStream = new MemoryStream();


                // Create a CryptoStream using the MemoryStream  
              
                CryptoStream cStream = new CryptoStream(mStream, encrypter.CreateEncryptor(), CryptoStreamMode.Write);

                // Convert the passed string to a byte array. 
                byte[] toEncrypt = new ASCIIEncoding().GetBytes(Data);

                // Write the byte array to the crypto stream and flush it.
                cStream.Write(toEncrypt, 0, toEncrypt.Length);
                cStream.FlushFinalBlock();

                // Get an array of bytes from the  
                // MemoryStream that holds the  
                // encrypted data. 
                byte[] ret = mStream.ToArray();

                // Close the streams.
                cStream.Close();
                mStream.Close();
                // Return the encrypted and Encoded string.   
             
                return Convert.ToBase64String(ret);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Decryption Method
        /// </summary>
        /// <param name="Data">The Data to be decrypted</param>
        /// <param name="Key">The key for the decryption algorithm</param>
        /// <param name="IV">the Intialization vector </param>
        /// <returns></returns>
        public string DecryptAndDecodeText(String Data)
        {
            try
            {
                // Create a new MemoryStream using the passed array of encrypted data
                byte[] decodedData = Convert.FromBase64String(Data);
                MemoryStream msDecrypt = new MemoryStream(decodedData);
                

                // Create a CryptoStream using the MemoryStream
                CryptoStream csDecrypt = new CryptoStream(msDecrypt, encrypter.CreateDecryptor(), CryptoStreamMode.Read);

                // Create buffer to hold the decrypted data. 
                byte[] fromEncrypt = new byte[Data.Length];

                // Read the decrypted data out of the crypto stream 
                // and place it into the temporary buffer.
                csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);

                //Convert the buffer into a string and return it. 
                return new ASCIIEncoding().GetString(fromEncrypt);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
    }
}
