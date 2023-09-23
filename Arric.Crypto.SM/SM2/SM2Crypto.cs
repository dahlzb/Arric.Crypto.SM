using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// SM2加密
    /// <para>密文数据顺序，新标准（C1 C3 C2），老标准（C1 C2 C3）</para>
    /// </summary>
    public class SM2Crypto
    {
        /// <summary>
        /// 生成密钥（公钥、私钥）
        /// </summary>
        /// <returns>公钥，私钥</returns>
        public (byte[] PublicKey, byte[] PrivateKey) GenerateSecretKeyPair()
        {
            SM2EccParam sM2EccParam = new SM2EccParam();
            AsymmetricCipherKeyPair key = sM2EccParam.EccKeyPairGenerator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            Org.BouncyCastle.Math.EC.ECPoint publicKey = ecpub.Q;

            return (publicKey.GetEncoded(), privateKey.ToByteArray());
        }

        /// <summary>
        /// 生成密钥（公钥、私钥）
        /// </summary>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <returns></returns>
        public (string PublicKey, string PrivateKey) GenerateSecretKeyPair(bool isHexSecretKey = true)
        {
            var generateResult = this.GenerateSecretKeyPair();
            var publicKeyBytes = isHexSecretKey ? Hex.Encode(generateResult.PublicKey) : Base64.Encode(generateResult.PublicKey);
            var privateKeyBytes = isHexSecretKey ? Hex.Encode(generateResult.PrivateKey) : Base64.Encode(generateResult.PrivateKey);

            return (Encoding.UTF8.GetString(publicKeyBytes), Encoding.UTF8.GetString(privateKeyBytes));
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plaintext, byte[] publicKey, bool isNewStandard = true)
        {
            if (null == publicKey || publicKey.Length == 0) return null;
            if (plaintext == null || plaintext.Length == 0) return null;

            byte[] c2 = new byte[plaintext.Length];
            Array.Copy(plaintext, 0, c2, 0, plaintext.Length);

            var cipher = new Cipher();
            var sM2EccParam = new SM2EccParam();
            var userKey = sM2EccParam.EccCurve.DecodePoint(publicKey);
            var c1 = cipher.InitEnc(sM2EccParam, userKey).GetEncoded();
            cipher.Encrypt(c2);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            var encryptBytes = new List<byte>();
            // 密文顺序
            if (isNewStandard) encryptBytes = c1.Concat(c3).Concat(c2).ToList();
            else encryptBytes = c1.Concat(c2).Concat(c3).ToList();
            return encryptBytes.ToArray();
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public byte[] Encrypt(string plaintext, string publicKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            var publicKeyBytes = isHexSecretKey ? Hex.Decode(publicKey) : Base64.Decode(publicKey);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            return Encrypt(plaintextBytes, publicKeyBytes, isNewStandard);
        }

        /// <summary>
        /// 将明文加密成Base64字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public string EncryptToBase64(string plaintext, string publicKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            return Base64.ToBase64String(Encrypt(plaintext, publicKey, isHexSecretKey, isNewStandard));
        }

        /// <summary>
        /// 将明文加密成Hex字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public string EncryptToHex(string plaintext, string publicKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            return Hex.ToHexString(Encrypt(plaintext, publicKey, isHexSecretKey, isNewStandard));
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] ciphertext, byte[] privateKey, bool isNewStandard = true)
        {
            if (null == privateKey || privateKey.Length == 0) return null;
            if (ciphertext == null || ciphertext.Length == 0) return null;

            var sM2EccParam = new SM2EccParam();
            var data = Encoding.UTF8.GetString(Hex.Encode(ciphertext));
            int c2Len = ciphertext.Length - 97;
            var c1Str = data.Substring(0, 130);
            var c2Str = isNewStandard ? data.Substring(130 + 64, 2 * c2Len) : data.Substring(130, 2 * c2Len);
            var c3Str = isNewStandard ? data.Substring(130, 64) : data.Substring(130 + 2 * c2Len, 64);

            var c1Bytes = Hex.Decode(Encoding.UTF8.GetBytes(c1Str));
            var c2Bytes = Hex.Decode(Encoding.UTF8.GetBytes(c2Str));
            var c3Bytes = Hex.Decode(Encoding.UTF8.GetBytes(c3Str));

            BigInteger userD = new BigInteger(1, privateKey);
            var c1 = sM2EccParam.EccCurve.DecodePoint(c1Bytes);

            Cipher cipher = new Cipher();
            cipher.InitDec(userD, c1);
            cipher.Decrypt(c2Bytes);
            cipher.Dofinal(c3Bytes);

            return c2Bytes;
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] ciphertext, string privateKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            var privateKeyBytes = isHexSecretKey ? Hex.Decode(privateKey) : Base64.Decode(privateKey);
            return Decrypt(ciphertext, privateKeyBytes, isNewStandard);
        }

        /// <summary>
        /// 将Hex字符串密文解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public string DecryptFormBase64(string ciphertext, string privateKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            var ciphertextBytes = Base64.Decode(ciphertext);
            return Encoding.UTF8.GetString(Decrypt(ciphertextBytes, privateKey, isHexSecretKey, isNewStandard));
        }

        /// <summary>
        /// 将Base64字符串密文解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexSecretKey">是否生成16进制密钥，否则为Base64</param>
        /// <param name="isNewStandard">密文数据顺序是否为新标准</param>
        /// <returns></returns>
        public string DecryptFormHex(string ciphertext, string privateKey, bool isHexSecretKey = true, bool isNewStandard = true)
        {
            var ciphertextBytes = Hex.Decode(ciphertext);
            return Encoding.UTF8.GetString(Decrypt(ciphertextBytes, privateKey, isHexSecretKey, isNewStandard));
        }
    }
}