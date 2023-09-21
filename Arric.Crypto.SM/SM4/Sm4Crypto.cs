using Microsoft.SqlServer.Server;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arric.Crypto.SM.SM4
{
    /// <summary>
    /// Sm4算法  
    /// <para>对标国际DES算法</para>
    /// </summary>
    public class Sm4Crypto
    {

        // <summary>
        /// 文本编码格式
        /// </summary>
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        #region ECB

        /// <summary>
        /// ECB加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public byte[] EncryptECB(string plaintext, string secretKey, bool isHexSecretKey = false)
        {
            Sm4Context ctx = new Sm4Context
            {
                IsPadding = true
            };

            byte[] keyBytes = isHexSecretKey ? Hex.Decode(secretKey) : this.Encoding.GetBytes(secretKey);

            SM4 sm4 = new SM4();
            sm4.SetKeyEnc(ctx, keyBytes);
            byte[] encrypted = sm4.Sm4CryptECB(ctx, this.Encoding.GetBytes(plaintext));

            return encrypted;
        }

        /// <summary>
        /// 将明文通过ECB加密成Base64字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public string EncryptECBToBase64(string plaintext, string secretKey, bool isHexSecretKey = false)
        {
            return Convert.ToBase64String(this.EncryptECB(plaintext, secretKey, isHexSecretKey));
        }

        /// <summary>
        /// 将明文通过ECB加密成Hex字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public string EncryptECBToHex(string plaintext, string secretKey, bool isHexSecretKey = false)
        {
            return Encoding.UTF8.GetString(Hex.Encode(this.EncryptECB(plaintext, secretKey, isHexSecretKey)));
        }

        /// <summary>
        /// ECB解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptECB(byte[] ciphertext, string secretKey, bool isHexSecretKey = false)
        {
            Sm4Context ctx = new Sm4Context
            {
                IsPadding = true,
                Mode = 0
            };

            byte[] keyBytes = isHexSecretKey ? Hex.Decode(secretKey) : this.Encoding.GetBytes(secretKey);

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyDec(ctx, keyBytes);
            byte[] decrypted = sm4.Sm4CryptECB(ctx, ciphertext);
            return Encoding.GetString(decrypted);
        }

        /// <summary>
        /// 将Base64字符串密文进行ECB解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptECBFormBase64(string ciphertext, string secretKey, bool isHexSecretKey = false)
        {
            return DecryptECB(Convert.FromBase64String(ciphertext), secretKey, isHexSecretKey);
        }

        /// <summary>
        /// 将Hex字符串密文进行ECB解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptECBFormHex(string ciphertext, string secretKey, bool isHexSecretKey = false)
        {
            return DecryptECB(Hex.Decode(ciphertext), secretKey, isHexSecretKey);
        }

        #endregion

        #region CBC

        /// <summary>
        /// CBC加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public byte[] EncryptCBC(string plaintext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            Sm4Context ctx = new Sm4Context
            {
                IsPadding = true
            };

            byte[] keyBytes = isHexSecretKey ? Hex.Decode(secretKey) : this.Encoding.GetBytes(secretKey);
            byte[] ivBytes = isHexIv ? Hex.Decode(iv) : this.Encoding.GetBytes(iv);

            SM4 sm4 = new SM4();
            sm4.SetKeyEnc(ctx, keyBytes);
            byte[] encrypted = sm4.Sm4CryptCBC(ctx, ivBytes, this.Encoding.GetBytes(plaintext));

            return encrypted;
        }

        /// <summary>
        /// 将明文通过CBC加密成Base64字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public string EncryptCBCToBase64(string plaintext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            return Convert.ToBase64String(this.EncryptCBC(plaintext, secretKey, iv, isHexSecretKey, isHexIv));
        }

        /// <summary>
        /// 将明文通过CBC加密成Hex字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public string EncryptCBCToHex(string plaintext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            return Encoding.UTF8.GetString(Hex.Encode(this.EncryptCBC(plaintext, secretKey, iv, isHexSecretKey, isHexIv)));
        }

        /// <summary>
        /// CBC解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptCBC(byte[] ciphertext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            Sm4Context ctx = new Sm4Context
            {
                IsPadding = true,
                Mode = 0
            };

            byte[] keyBytes = isHexSecretKey ? Hex.Decode(secretKey) : this.Encoding.GetBytes(secretKey);
            byte[] ivBytes = isHexIv ? Hex.Decode(iv) : this.Encoding.GetBytes(iv);

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyDec(ctx, keyBytes);
            byte[] decrypted = sm4.Sm4CryptCBC(ctx, ivBytes, ciphertext);
            return Encoding.GetString(decrypted);
        }

        /// <summary>
        /// 将Base64字符串密文进行CBC解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptCBCFormBase64(string ciphertext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            return DecryptCBC(Convert.FromBase64String(ciphertext), secretKey, iv, isHexSecretKey, isHexIv);
        }

        /// <summary>
        /// 将Hex字符串密文进行CBC解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexSecretKey">密钥是否为16进制字符串</param>
        /// <param name="isHexIv">iv是否为16进制字符串</param>
        /// <returns></returns>
        public string DecryptCBCFormHex(string ciphertext, string secretKey, string iv, bool isHexSecretKey = false, bool isHexIv = false)
        {
            return DecryptCBC(Hex.Decode(ciphertext), secretKey, iv, isHexSecretKey, isHexIv);
        }

        #endregion
    }
}
