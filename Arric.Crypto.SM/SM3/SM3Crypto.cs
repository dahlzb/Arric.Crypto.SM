using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Arric.Crypto.SM.SM3
{
    /// <summary>
    /// SM3加密（完整性运算）
    /// <para>相当于SHA256</para>
    /// </summary>
    public class SM3Crypto
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plaintext)
        {
            byte[] md = new byte[32];
            SM3Digest sm3 = new SM3Digest();
            sm3.BlockUpdate(plaintext, 0, plaintext.Length);
            sm3.DoFinal(md, 0);

            return md;
        }

        /// <summary>
        /// 将明文加密成Base64字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <returns></returns>
        public string EncryptToBase64(string plaintext)
        {
            return Base64.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plaintext)));
        }

        /// <summary>
        /// 将明文加密成Hex字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <returns></returns>
        public string EncryptToHex(string plaintext)
        {
            return Hex.ToHexString(Encrypt(Encoding.UTF8.GetBytes(plaintext)));
        }
    }
}
