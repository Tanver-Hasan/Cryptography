using System;
using System.Security.Cryptography;

namespace Crypto{
    class Hash
    {
        public static byte[] GenerateSalt(){
            const int saltLength=32;
            using(var randomNumberGenerator= new RNGCryptoServiceProvider()){
                var random= new byte[saltLength];
                randomNumberGenerator.GetBytes(random);
                return random;
            }
        }

        public static byte[] Combine(byte[] first, byte[] second){
            var ret= new byte[first.Length+second.Length];
            Buffer.BlockCopy(first,0,ret,0,first.Length);
            Buffer.BlockCopy(second,0,ret,first.Length,second.Length);
            return ret;
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt){
            using(var sha256= SHA256.Create()){
                return sha256.ComputeHash(Combine(toBeHashed,salt));
            }
        }
    }
}