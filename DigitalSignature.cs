using System;
using System.IO;
using System.Security.Cryptography;

namespace Crypto
{
    public class DigitalSignature
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public  void AssignKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                this._publicKey=rsa.ExportParameters(false);
                this._privateKey=rsa.ExportParameters(true);
            }
        }

        public byte[] SignData(byte[] hasghOfDataToSign){
            using(var rsa=new RSACryptoServiceProvider(2048)){
                rsa.PersistKeyInCsp=false;
                rsa.ImportParameters(this._privateKey);
                var rsaFormatter= new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA25");
                return rsaFormatter.CreateSignature(hasghOfDataToSign);
            }
        }

        public bool VerifySignature(byte[] hasOfDataToSign, byte[] signature){
            using(var rsa= new RSACryptoServiceProvider(2048)){
                rsa.ImportParameters(this._publicKey);
                var rsaDeformater=new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformater.SetHashAlgorithm("SHA256");
                return rsaDeformater.VerifySignature(hasOfDataToSign,signature);
            }
        }
    }
}