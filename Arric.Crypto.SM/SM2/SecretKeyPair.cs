using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// 密钥对
    /// </summary>
    public class SecretKeyPair
    {
        /// <summary>
        /// 密钥对
        /// </summary>
        public SecretKeyPair()
        {
        }

        /// <summary>
        /// 密钥对
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="privateKey">私钥</param>
        public SecretKeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        /// <summary>
        /// 公钥
        /// </summary>
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// 私钥
        /// </summary>
        public byte[] PrivateKey { get; set; }
    }
}
