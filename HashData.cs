using System;
using System.Security.Cryptography;
namespace Crypto
{
    public class HashData
    {
        public static byte[] ComputeHashSha25(byte[] toBeHashed)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha512(byte[] toBeHashed)
        {
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashMD5(byte[] toBeHashed){
            using(var md5=MD5.Create()){
                return md5.ComputeHash(toBeHashed);
            }
        }
    }

}