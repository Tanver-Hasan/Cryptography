using System;
using System.Security.Cryptography;

namespace Crypto
{
   public class HMAC
    {
        private static int keySize=32;

        public static byte[] GenerateKey(){
            using(var randomNumberGenerator= new RNGCryptoServiceProvider()){
                var randomNumber=new byte[keySize];
                randomNumberGenerator.GetBytes(randomNumber);

                return randomNumber;
            }
        }
        public static byte[] ComputeHmacSah256(byte[] toBeHashed, byte[] key)
        {
            using (var hmacSah256 = new HMACSHA256(key))
            {
                return hmacSah256.ComputeHash(toBeHashed);
            }

        }
        
       public static byte[] ComputeHmacSah512(byte[] toBeHashed, byte[] key)
        {
            using (var hmacSah256 = new HMACSHA512(key))
            {
                return hmacSah256.ComputeHash(toBeHashed);
            }

        }

           public static byte[] ComputeHmacMD5(byte[] toBeHashed, byte[] key)
        {
            using (var hmacMd5= new HMACMD5(key))
            {
                return hmacMd5.ComputeHash(toBeHashed);
            }

        }
    }
}