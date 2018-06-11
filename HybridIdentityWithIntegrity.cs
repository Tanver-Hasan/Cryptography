using System;
using System.Security.Cryptography;

namespace Crypto
{

    public class HybridEncryptionWithIntegrity
    {

        AesEncryption _aes = new AesEncryption();


        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            var sessionKey = _aes.GenerateRandomNumber(32);
            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

            using (var hmac = new HMACSHA256(sessionKey))
            {
                encryptedPacket.Hmac = hmac.ComputeHash(encryptedPacket.EncryptedData);
            }
            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
        {
            var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);
            using (var hmac = new HMACSHA256(decryptedSessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(encryptedPacket.EncryptedData);
                if (!Compare(encryptedPacket.Hmac, hmacToCheck))
                {
                    throw new CryptographicException("HMAC for encryption does not match with encrypted packet");
                }
            }
            var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);
            return decryptedData;
        }
        private static bool Compare(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;

            for (var i = 0; i < array1.Length && i < array2.Length; i++)
            {
                result &= array1[i] == array2[i];
            }
            return result;
        }
    }
}



