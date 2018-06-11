using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Crypto
{
    class Program
    {

        static void Main(string[] args)
        {


            // HybridEncryptionTest();
            HybridEncryptionWithIntegrityCheckTest();
            Console.ReadKey();
        }

        private static void HasPasswordExample()
        {
            const string password = "MyNameIsTanverHasan";
            byte[] salt = Hash.GenerateSalt();
            Console.WriteLine("Hash Password with salt demonastration in .Net");
            Console.WriteLine("password : " + password);
            System.Console.WriteLine("Salt : " + Convert.ToBase64String(salt));
            var hashPassword = Hash.HashPasswordWithSalt(Encoding.UTF8.GetBytes(password), salt);
            Console.WriteLine("HashPassword :" + Convert.ToBase64String(hashPassword));
        }

        private static SigningCredentials GetSigningCredentials(SymmetricSecurityKey securityKey)
        {
            return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        }

        private static byte[] GenerateRandomNumber(int length)
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[length];

                randomNumberGenerator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        private static void HybridEncryptionTest()
        {
            const string original = "Very secret data. After message";
            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignKey();
            var hybrid = new HybridEncryption();

            var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
            var decrypted = hybrid.DecryptData(encryptedBlock, rsaParams);

            Console.WriteLine();
            Console.WriteLine(Encoding.UTF8.GetString(decrypted));
        }

        private static void HybridEncryptionWithIntegrityCheckTest()
        {
            const string original = "Very secret data. After message";
            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignKey();
            var hybrid = new HybridEncryptionWithIntegrity();

            var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
            var decrypted = hybrid.DecryptData(encryptedBlock, rsaParams);

            Console.WriteLine();
            Console.WriteLine(Encoding.UTF8.GetString(decrypted));
        }

    }
}
