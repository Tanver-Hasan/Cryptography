using System;
using System.IO;
using System.Security.Cryptography;

namespace Crypto
{
    class RSAWithXMLKey
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public void AssignKey(string publicKeyPath, string privateKeypath)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                if (File.Exists(privateKeypath))
                {
                    File.Delete(privateKeypath);
                }

                if (File.Exists(publicKeyPath))
                {
                    File.Delete(publicKeyPath);
                }

                var publicKeyFolder = Path.GetDirectoryName(publicKeyPath);
                var privateKeyFolder = Path.GetDirectoryName(privateKeypath);

                if (!Directory.Exists(publicKeyFolder))
                {
                    Directory.CreateDirectory(publicKeyFolder);
                }
                if(!Directory.Exists(privateKeyFolder)){
                    Directory.CreateDirectory(privateKeyFolder);
                }

                File.WriteAllText(publicKeyFolder,rsa.ToXmlString(false));
                File.WriteAllText(privateKeypath,rsa.ToXmlString(true));

                this._publicKey = rsa.ExportParameters(false);
                this._privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] EncryptData(string publicKeyPath,byte[] dataToEncrypt)
        {
            byte[] cipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                cipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cipherBytes;
        }
        public byte[] DecryptData(string privateKeyPath,byte[] dataToDecrypt)
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(privateKeyPath));
                plain = rsa.Decrypt(dataToDecrypt, true);
            }
            return plain;
        }
    }
}










