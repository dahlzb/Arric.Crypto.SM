using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// 密钥对16进制字符串
    /// </summary>
    public class SecretKeyPairHex
    {
        /// <summary>
        /// 密钥对16进制字符串
        /// </summary>
        public SecretKeyPairHex()
        {
        }

        /// <summary>
        /// 密钥对16进制字符串
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        public SecretKeyPairHex(string publicKey, string privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        /// <summary>
        /// 公钥
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// 私钥
        /// </summary>
        public string PrivateKey { get; set; }
    }
}
