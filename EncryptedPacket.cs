using System;
using System.Security.Cryptography;

namespace Crypto
{
    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;

        public byte[] Iv;

        public byte[] Hmac;
        public byte[] Signature;
    }
}