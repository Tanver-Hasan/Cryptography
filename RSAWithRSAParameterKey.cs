using System;
using System.Security.Cryptography;

namespace Crypto
{
    public class RSAWithRSAParameterKey
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public void AssignKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                this._publicKey = rsa.ExportParameters(false);
                this._privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] EncryptData(byte[] dataToEncrypt)
        {
            byte[] cipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_publicKey);
                cipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cipherBytes;
        }
        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);
                plain = rsa.Decrypt(dataToDecrypt, true);
            }
            return plain;
        }
    }
}