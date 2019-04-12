using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Text;

namespace testRsa
{
    class Program
    {
      

        static void Main(string[] args)
        {
            //Generate 1024 Key Pair
            var kpgen = new RsaKeyPairGenerator();
            kpgen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var keyPair = kpgen.GenerateKeyPair();


            //Write publickey in Pem Format
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keyPair.Public);
            pemWriter.Writer.Flush();
            String publicKey = textWriter.ToString();

            //Write privatekey in Pem Format
            TextWriter textWriter1 = new StringWriter();
            PemWriter pemWriter1 = new PemWriter(textWriter1);
            pemWriter1.WriteObject(keyPair.Private);
            pemWriter1.Writer.Flush();
            String current_privateKey = textWriter1.ToString();
            
            //Encrypt Text
            string encryptedText = RsaEncryptWithPublic("test", publicKey);
            
            //Decrypt Text
            string result = RsaDecryptWithPrivate( encryptedText, current_privateKey);

            //Print Result
            Console.WriteLine(result);
            Console.ReadKey();
        }

        //Encrypt method
        public static string RsaEncryptWithPublic(string clearText, string publicKey)
        {
            //Encode text to bytes
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            //Initialize Rsa Engine
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            //Read pem 
            using (var txtreader = new StringReader(publicKey))
            {
                //cast publickey to asymmetric key parameter
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                //Set engine for encryption( true means that parameter is used for encryption)
                encryptEngine.Init(true, keyParameter);
            }

            // encrypt bytes block and converts it to base64string
            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));

            //Return decrypted string
            return encrypted;

        }
        
        //Decrypt method
        public static string RsaDecryptWithPrivate(string base64Input, string privateKey)
        {
            //Encode text to bytes
            var bytesToDecrypt = Convert.FromBase64String(base64Input);
            //Initialize Rsa Engine
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            //Read Pem
            using (var txtreader = new StringReader(privateKey))
            {
                //cast privatekey to asymmetric cipher keypair because rsa private key always contains public key
                var keyParameter = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                //Set engine for decryption
                decryptEngine.Init(false, keyParameter.Private);
            }

            // decrypt bytes block and converts it to Utf8 string
            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));

            //Return decrypted string
            return decrypted;
        }
    }
}
