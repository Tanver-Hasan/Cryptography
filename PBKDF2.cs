using System;
using System.Security.Cryptography;

namespace Cypto
{
    class PBKDBF2
    {
        public static byte[] GenerateSalt()
        {
            const int saltLength = 32;
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var random = new byte[saltLength];
                randomNumberGenerator.GetBytes(random);
                return random;
            }
        }

        public static byte[] HashPassword(byte[] toBeHashed, byte[] salt, int numberOfRound)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRound))
            {
                return rfc2898.GetBytes(32);
            }
        }
    }
}