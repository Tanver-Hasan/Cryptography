using System;
using System.Security.Cryptography;

namespace Crypto
{

    public class HybridEncryption
    {

        AesEncryption _aes = new AesEncryption();


        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            var sessionKey = _aes.GenerateRandomNumber(32);
            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);
            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
        {
            var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

            var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);
            return decryptedData;
        }

    }
}