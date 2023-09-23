using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arric.Crypto.SM.Tests
{
    [TestClass]
    public class SM2UnitTest
    {
        private readonly string Plaintext = "Hello,World! 【你好，世界！】 {1234}";
        private readonly string PublicKeyHex = "0438d6c61846227b6aacfe63c04450743ea290cfea03bbc520f2f2fc1390e1f6ee8ad78a30d6be15a4cf0cf70ad663ab010c5376e9af9ec6e19e949df724a64156";
        private readonly string PrivateKeyHex = "3ce883d07c7af373cd920d43983a273fd98996ec98d1dfe2efc7fb7d8df0d0c2";
        private readonly string PublicKeyBase64 = "BCz9I6VgX3ucUeOSqKx9Ps0oobjapqq56Xqy3Ih8IJrJIlBAI8IX3sJzsl9ieYNcHSpFbbzf4aOGmtfOPtjpHp4=";
        private readonly string PrivateKeyBase64 = "AIo78qWKZTbZ/oJS3d2PMBrVlv8qEcpu88ouuv1gK3zg";

        [TestMethod("SM2 生成公钥/私钥")]
        public void GenerateKey()
        {
            var sm2 = new SM2.SM2Crypto();
            var generateKeyHex = sm2.GenerateSecretKeyPair(true);
            var generateKeyBase64 = sm2.GenerateSecretKeyPair(false);
            Assert.IsNotNull(generateKeyHex);
            Assert.IsNotNull(generateKeyBase64);
        }

        [TestMethod("SM2 加密 Hex密钥 新标准")]
        public void EncryptHexSecretKeyNewStandard()
        {
            var sm2 = new SM2.SM2Crypto();

            var encHex = sm2.EncryptToHex(Plaintext, PublicKeyHex, true);
            var encBase64 = sm2.EncryptToBase64(Plaintext, PublicKeyHex, true);
            var decHex = sm2.DecryptFormHex(encHex, PrivateKeyHex, true);
            var decBase64 = sm2.DecryptFormBase64(encBase64, PrivateKeyHex, true);
            Assert.AreEqual(Plaintext, decHex);
            Assert.AreEqual(Plaintext, decBase64);
        }

        [TestMethod("SM2 加密 Base64密钥 新标准")]
        public void EncryptBase64SecretKeyNewStandard()
        {
            var sm2 = new SM2.SM2Crypto();

            var encHex = sm2.EncryptToHex(Plaintext, PublicKeyBase64, false);
            var encBase64 = sm2.EncryptToBase64(Plaintext, PublicKeyBase64, false);
            var decHex = sm2.DecryptFormHex(encHex, PrivateKeyBase64, false);
            var decBase64 = sm2.DecryptFormBase64(encBase64, PrivateKeyBase64, false);
            Assert.AreEqual(Plaintext, decHex);
            Assert.AreEqual(Plaintext, decBase64);
        }

        [TestMethod("SM2 加密 Hex密钥 旧标准")]
        public void EncryptHexSecretKeyOldStandard()
        {
            var sm2 = new SM2.SM2Crypto();

            var encHex = sm2.EncryptToHex(Plaintext, PublicKeyHex, true,false);
            var encBase64 = sm2.EncryptToBase64(Plaintext, PublicKeyHex, true, false);
            var decHex = sm2.DecryptFormHex(encHex, PrivateKeyHex, true, false);
            var decBase64 = sm2.DecryptFormBase64(encBase64, PrivateKeyHex, true, false);
            Assert.AreEqual(Plaintext, decHex);
            Assert.AreEqual(Plaintext, decBase64);
        }

        [TestMethod("SM2 加密 Base64密钥 旧标准")]
        public void EncryptBase64SecretKeyOldStandard()
        {
            var sm2 = new SM2.SM2Crypto();

            var encHex = sm2.EncryptToHex(Plaintext, PublicKeyBase64, false, false);
            var encBase64 = sm2.EncryptToBase64(Plaintext, PublicKeyBase64, false, false);
            var decHex = sm2.DecryptFormHex(encHex, PrivateKeyBase64, false, false);
            var decBase64 = sm2.DecryptFormBase64(encBase64, PrivateKeyBase64, false, false);
            Assert.AreEqual(Plaintext, decHex);
            Assert.AreEqual(Plaintext, decBase64);
        }
    }
}
