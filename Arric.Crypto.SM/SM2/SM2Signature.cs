using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// SM2加签验签
    /// </summary>
    public class SM2Signature
    {
        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="plaintextBytes">待签名数据</param>
        /// <param name="privateKeyBytes">私钥</param>
        /// <returns>签名结果</returns>
        public static byte[] GenerateSignature(byte[] plaintextBytes, byte[] privateKeyBytes)
        {
            // 1. 获取SM2曲线参数
            var ecParams = GMNamedCurves.GetByName("sm2p256v1");
            var domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);
            // 2. 构造私钥参数
            var d = new BigInteger(1, privateKeyBytes);
            var priParams = new ECPrivateKeyParameters(d, domainParameters);

            // 3. 构造SM2签名器
            var signer = new SM2Signer();
            signer.Init(true, priParams);
            signer.BlockUpdate(plaintextBytes, 0, plaintextBytes.Length);

            // 4. 生成签名
            return signer.GenerateSignature();
        }

        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="plaintext">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexPrivateKey">是否为16进制私钥，否则为Base64</param>
        /// <returns>签名结果</returns>
        public static byte[] GenerateSignature(string plaintext, string privateKey, bool isHexPrivateKey = true)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var privateKeyBytes = isHexPrivateKey ? Hex.Decode(privateKey) : Base64.Decode(privateKey);
            return GenerateSignature(plaintextBytes, privateKeyBytes);
        }

        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="plaintext">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexPrivateKey">是否为16进制私钥，否则为Base64</param>
        /// <returns>签名结果</returns>
        public static string GenerateSignatureToBase64(string plaintext, string privateKey, bool isHexPrivateKey = true)
        {
            return Base64.ToBase64String(GenerateSignature(plaintext, privateKey, isHexPrivateKey));
        }

        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="plaintext">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="isHexPrivateKey">是否为16进制私钥，否则为Base64</param>
        /// <returns>签名结果</returns>
        public static string GenerateSignatureToHex(string plaintext, string privateKey, bool isHexPrivateKey = true)
        {
            return Hex.ToHexString(GenerateSignature(plaintext, privateKey, isHexPrivateKey));
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="plaintextBytes">原始数据</param>
        /// <param name="signatureBytes">签名</param>
        /// <param name="publicKeyBytes">公钥</param>
        /// <returns>验签结果</returns>
        public static bool VerifySignature(byte[] plaintextBytes, byte[] signatureBytes, byte[] publicKeyBytes)
        {
            // 1. 获取SM2曲线参数
            var ecParams = GMNamedCurves.GetByName("sm2p256v1");
            var domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);

            // 2. 构造公钥参数
            var q = ecParams.Curve.DecodePoint(publicKeyBytes);
            var pubParams = new ECPublicKeyParameters(q, domainParameters);

            // 3. 构造SM2验签器
            var verifier = new SM2Signer();
            verifier.Init(false, pubParams);
            verifier.BlockUpdate(plaintextBytes, 0, plaintextBytes.Length);

            // 4. 验证签名
            return verifier.VerifySignature(signatureBytes);
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="plaintext">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="isHexPublicKey">是否为16进制公钥，否则为Base64</param>
        /// <param name="isHexSignature">是否为16进制签名，否则为Base64</param>
        /// <returns>验签结果</returns>
        public static bool VerifySignature(string plaintext, string signature, string publicKey, bool isHexPublicKey = true, bool isHexSignature = true)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var signatureBytes = isHexSignature ? Hex.Decode(signature) : Base64.Decode(signature); 
            var publicKeyBytes = isHexPublicKey ? Hex.Decode(publicKey) : Base64.Decode(publicKey);

            return VerifySignature(plaintextBytes, signatureBytes, publicKeyBytes);
        }
    }
}
