using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {

            byte[] kaynak = File.ReadAllBytes(@"C:\Users\Dilan\Desktop\alan\main.c");
            string kaynakstr = Encoding.UTF8.GetString(kaynak);

            //AES(kaynak, kaynakstr);

            //RC2(kaynakstr);

            //RSA(kaynak, kaynakstr);
        }

        private static void AES(byte[] kaynak, string kaynakstr)
        {
            string path = @"C:\Users\Dilan\Desktop\alan\main.c";
            string crptoPath = @"C:\Users\Dilan\Desktop\crpto\AlanAES.c";

            // Create a new instance of the AES
            // class.  This generates a new key and initialization 
            // vector (IV).
            using (Aes myAes = Aes.Create())
            {
                myAes.GenerateKey();
                myAes.GenerateIV();

               
                byte[] encrypted = AESEncryptStringToBytes(kaynakstr, myAes.Key, myAes.IV);
                string encryptedstring = Encoding.UTF8.GetString(encrypted);
                File.WriteAllText(crptoPath, encryptedstring);

                StringBuilder s = new StringBuilder();
                foreach (byte item in encrypted)
                {
                    s.Append(item.ToString("X2") + " ");
                }

                string decrypted = AESDecryptStringFromBytes(encrypted, myAes.Key, myAes.IV);

                
                File.WriteAllText(path, decrypted);

                Console.WriteLine("AES algorithm Crypted : {0} \n\n\n plaintext: {1}", encryptedstring, decrypted);
                Console.ReadKey();
            }

        }

        private static string AESDecryptStringFromBytes(byte[] encrypted, byte[] Key, byte[] IV)
        {

            
            string plaintext = null;

         
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.Zeros;
                
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
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

        private static byte[] AESEncryptStringToBytes(string kaynakstr, byte[] key, byte[] IV)
        {

            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.Zeros;
                
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(kaynakstr);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        private static void RSA(byte[] kaynak, string kaynakstr)
        {
            string path = @"C:\Users\Dilan\Desktop\alan\main.c";
            string crptoPath = @"C:\Users\Dilan\Desktop\crpto\AlanRSA.c";
            byte[] kaynakstring = Encoding.UTF8.GetBytes(kaynakstr);

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            
            byte[] encryptedData;
            byte[] decryptedData;
            
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                encryptedData = RSAEncrypt(kaynakstring, RSA.ExportParameters(false), false);

                string encryptedstring = Encoding.UTF8.GetString(encryptedData);
                File.WriteAllText(crptoPath, encryptedstring);

                decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);
                string decryptedstring = Encoding.UTF8.GetString(decryptedData);
                File.WriteAllText(path, decryptedstring);
 
                Console.WriteLine("RSA Decrypted : {0} \n\n\n  encrypted: {1}", decryptedstring, encryptedstring);
                Console.ReadKey();
            }
        }

        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);

                
                encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            return encryptedData;

        }

        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            byte[] decryptedData;
           
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);
  
                decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
            }
            return decryptedData;
        }


        public static void RC2(string kaynakstr)
        {
            string path = @"C:\Users\Dilan\Desktop\alan\main.c";
            string crptoPath = @"C:\Users\Dilan\Desktop\crpto\AlanRC2.c";

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            string encryptedstring = Sifrele(kaynakstr);
            File.WriteAllText(crptoPath, encryptedstring);

            string decrypted = Coz(encryptedstring);
            File.WriteAllText(path, decrypted);
            Console.WriteLine("Crypted plaintext: {0} \n {1}", encryptedstring, decrypted);
            Console.ReadKey();
        }

        public static string Sifrele(string strGiris)
        {
            string sonuc = "";
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] aryKey = ByteConverter.GetBytes("12345678");
            byte[] aryIV = ByteConverter.GetBytes("12345678");
            RC2CryptoServiceProvider dec = new RC2CryptoServiceProvider();
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
            StreamWriter writer = new StreamWriter(cs);
            writer.Write(strGiris);
            writer.Flush();
            cs.FlushFinalBlock();
            writer.Flush();
            sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
            writer.Dispose();
            cs.Dispose();
            ms.Dispose();

            return sonuc;
        }

        public static string Coz(string strGiris)
        {
            string strSonuc = "";
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] arySifre = ByteConverter.GetBytes(strGiris);

            byte[] aryKey = ByteConverter.GetBytes("12345678");
            byte[] aryIV = ByteConverter.GetBytes("12345678");
            RC2CryptoServiceProvider cp = new RC2CryptoServiceProvider();
            MemoryStream ms = new MemoryStream(Convert.FromBase64String(strGiris));
            CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
            StreamReader reader = new StreamReader(cs);
            strSonuc = reader.ReadToEnd();
            reader.Dispose();
            cs.Dispose();
            ms.Dispose();

            return strSonuc;
        }
    }
}
