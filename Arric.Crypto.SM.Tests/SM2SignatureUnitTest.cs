using Arric.Crypto.SM.SM2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arric.Crypto.SM.Tests
{
    [TestClass]
    public class SM2SignatureUnitTest
    {
        private readonly string Plaintext = "Hello,World! 【你好，世界！】 {1234}";
        private readonly string PublicKeyHex = "0438d6c61846227b6aacfe63c04450743ea290cfea03bbc520f2f2fc1390e1f6ee8ad78a30d6be15a4cf0cf70ad663ab010c5376e9af9ec6e19e949df724a64156";
        private readonly string PrivateKeyHex = "3ce883d07c7af373cd920d43983a273fd98996ec98d1dfe2efc7fb7d8df0d0c2";
        private readonly string PublicKeyBase64 = "BN5DqRY9f8uOQvqsOh0kwUKa/aHLv5k76CxqOknigwzKVjcdjHKqY2VyNFF3XtoOm+CMt6kOcg7rqPJdN7zxVv8=";
        private readonly string PrivateKeyBase64 = "IxY+f/gIqrOAKWhhymbMF6TWud4O3w3a/Q0fY+4UQFg=";

        [TestMethod("SM2 验签 签名结果为Hex")]
        public void VerifySignatureHex()
        {
            var verifyHex = SM2Signature.VerifySignature(Plaintext, "304402206e1af1f59b719ba668f4a0663339dec0e07aab9b471958e188090314f1a78387022063d86f9dafa3314b4b2ca72fd7754682e9f8d28d1c84b3d12f7c6960cecb0e01", PublicKeyHex, true, true);
            var verifyBase64 = SM2Signature.VerifySignature(Plaintext, "304402201d1c805888724ece92027611b4d378e3871f2f4f6496330d4e8774bf3d479e23022049614eb2d401175dd14cedfceda788c64fc6019d56c8d1e5ad3becdec5b6c3d3", PublicKeyBase64, false, true);

            Assert.IsTrue(verifyHex);
            Assert.IsTrue(verifyBase64);
        }

        [TestMethod("SM2 验签 签名结果为Base64")]
        public void VerifySignatureBase64()
        {
            var verifyHex = SM2Signature.VerifySignature(Plaintext, "MEQCIC+FuTzVLvyufBHQuIrvSIOFw6RjNIPdR3KvYk50ijVJAiA1c+CY9Ua3iISa+zWCZ/PgAWKbpHh7BDjLFbRUPNnvrg==", PublicKeyHex, true, false);
            var verifyBase64 = SM2Signature.VerifySignature(Plaintext, "MEYCIQCoaA1YO0YsGnnon4NOtQg07PJsB4seqyXKXnK1iAwHdQIhAPxIQ9oTn3iUIqwtC2KIykYNkz3zT9fpxlaFz0XaR361", PublicKeyBase64, false, false);

            Assert.IsTrue(verifyHex);
            Assert.IsTrue(verifyBase64);
        }

        [TestMethod("SM2 加签 Hex私钥")]
        public void GenerateSignatureHexPrivateKey()
        {
            var signatureHex = SM2Signature.GenerateSignatureToHex(Plaintext, PrivateKeyHex, true);
            var signatureBase64 = SM2Signature.GenerateSignatureToBase64(Plaintext, PrivateKeyHex, true);


            var verifyHex = SM2Signature.VerifySignature(Plaintext, signatureHex, PublicKeyHex, true, true);
            var verifyBase64 = SM2Signature.VerifySignature(Plaintext, signatureBase64, PublicKeyHex, true, false);

            Assert.IsTrue(verifyHex);
            Assert.IsTrue(verifyBase64);
        }

        [TestMethod("SM2 加签 Base64私钥")]
        public void GenerateSignatureBase64PrivateKey()
        {
            var signatureHex = SM2Signature.GenerateSignatureToHex(Plaintext, PrivateKeyBase64, false);
            var signatureBase64 = SM2Signature.GenerateSignatureToBase64(Plaintext, PrivateKeyBase64, false);

            var verifyHex = SM2Signature.VerifySignature(Plaintext, signatureHex, PublicKeyBase64, false, true);
            var verifyBase64 = SM2Signature.VerifySignature(Plaintext, signatureBase64, PublicKeyBase64, false, false);

            Assert.IsTrue(verifyHex);
            Assert.IsTrue(verifyBase64);
        }
    }
}
