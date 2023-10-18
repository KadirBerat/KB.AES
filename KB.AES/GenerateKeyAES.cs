using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static KB.AES.CryptoServiceProvider;

namespace KB.AES
{
    internal class GenerateKeyAES
    {
        private string savePath = String.Empty;
        private int keySize = 192;
        internal GenerateKeyAES(string savePath)
        {
            this.savePath = savePath;
            this.keySize = 192;
        }
        internal GenerateKeyAES(string savePath, AESKeySize keySize)
        {
            this.savePath = savePath;
            switch (keySize)
            {
                case AESKeySize.AES_128_Sec:
                    this.keySize = 128;
                    break;
                case AESKeySize.AES_192_Rec:
                    this.keySize = 192;
                    break;
                case AESKeySize.AES_256_Sec:
                    this.keySize = 256;
                    break;
                default:
                    this.keySize = 192;
                    break;
            }
        }
        internal void GenerateKey()
        {
            using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
            {
                aesAlg.KeySize = keySize;
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();

                KeyIVModel keyAndIV = new KeyIVModel
                {
                    Key = aesAlg.Key,
                    IV = aesAlg.IV
                };

                string json = JsonConvert.SerializeObject(keyAndIV);

                string keyPath = $@"{savePath}\aes_key_iv.json";

                System.IO.File.WriteAllText(keyPath, json);
            }
        }
    }
}
