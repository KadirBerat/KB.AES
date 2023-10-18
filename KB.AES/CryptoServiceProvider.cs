using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KB.AES
{
    public class CryptoServiceProvider
    {
        /// <summary>
        /// Sec: Secure
        /// Rec: Recommended
        /// </summary>
        public enum AESKeySize
        {
            AES_128_Sec = 128,
            AES_192_Rec = 192,
            AES_256_Sec = 256
        }

        public void GenerateKey(string savePath) //AES_192_Rec
        {
            GenerateKeyAES gkAES = new GenerateKeyAES(savePath);
            gkAES.GenerateKey();
        }

        public void GenerateKey(string savePath, AESKeySize keySize)
        {
            GenerateKeyAES gkAES = new GenerateKeyAES(savePath, keySize);
            gkAES.GenerateKey();
        }

        public string Encrypt(string keyPath, string plainText)
        {
            KeyIVModel keyIV = GetKeyIV(keyPath);
            EncryptAES eAES = new EncryptAES(keyIV);
            return eAES.Encrypt(plainText);
        }

        public string Decrypt(string keyPath, string cipherText)
        {
            KeyIVModel keyIV = GetKeyIV(keyPath);
            DecryptAES dAES = new DecryptAES(keyIV);
            return dAES.Decrypt(cipherText);
        }

        private KeyIVModel GetKeyIV(string keyPath)
        {
            string json = File.ReadAllText(keyPath);
            var keyAndIV = JsonConvert.DeserializeObject<dynamic>(json);
            byte[] keyBytes = Convert.FromBase64String(keyAndIV.Key.ToString());
            byte[] ivBytes = Convert.FromBase64String(keyAndIV.IV.ToString());
            return new KeyIVModel { Key = keyBytes, IV = ivBytes };
        }

        public class KeyIVModel
        {
            public byte[] Key { get; set; }
            public byte[] IV { get; set; }
        }
    }
}
