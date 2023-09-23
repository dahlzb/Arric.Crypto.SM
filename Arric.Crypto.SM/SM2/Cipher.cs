using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// 密码计算
    /// </summary>
    internal class Cipher
    {
        private int ct = 1;

        /// <summary>
        /// 椭圆曲线E上点P2
        /// </summary>
        private ECPoint p2;
        private SM3Digest sm3keybase;
        private SM3Digest sm3c3;

        private readonly byte[] key = new byte[32];
        private byte keyOff = 0;

        private void Reset()
        {
            sm3keybase = new SM3Digest();
            sm3c3 = new SM3Digest();

            byte[] p = p2.Normalize().XCoord.ToBigInteger().ToByteArray();
            sm3keybase.BlockUpdate(p, 0, p.Length);
            sm3c3.BlockUpdate(p, 0, p.Length);

            p = p2.Normalize().YCoord.ToBigInteger().ToByteArray();
            sm3keybase.BlockUpdate(p, 0, p.Length);

            ct = 1;
            NextKey();
        }

        private void NextKey()
        {
            SM3Digest sm3keycur = new SM3Digest(sm3keybase);
            sm3keycur.Update((byte)(ct >> 24 & 0x00ff));
            sm3keycur.Update((byte)(ct >> 16 & 0x00ff));
            sm3keycur.Update((byte)(ct >> 8 & 0x00ff));
            sm3keycur.Update((byte)(ct & 0x00ff));
            sm3keycur.DoFinal(key, 0);
            keyOff = 0;
            ct++;
        }

        public virtual ECPoint InitEnc(SM2EccParam sm2, ECPoint userKey)
        {
            AsymmetricCipherKeyPair key = sm2.EccKeyPairGenerator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger k = ecpriv.D;
            ECPoint c1 = ecpub.Q;

            p2 = userKey.Multiply(k);
            Reset();

            return c1;
        }

        public virtual void Encrypt(byte[] data)
        {
            sm3c3.BlockUpdate(data, 0, data.Length);
            for (int i = 0; i < data.Length; i++)
            {
                if (keyOff == key.Length) NextKey();
                data[i] ^= key[keyOff++];
            }
        }

        public virtual void InitDec(BigInteger userD, ECPoint c1)
        {
            p2 = c1.Multiply(userD);
            Reset();
        }

        public virtual void Decrypt(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                if (keyOff == key.Length) NextKey();
                data[i] ^= key[keyOff++];
            }
            sm3c3.BlockUpdate(data, 0, data.Length);
        }

        public virtual void Dofinal(byte[] c3)
        {
            byte[] p = p2.Normalize().YCoord.ToBigInteger().ToByteArray();
            sm3c3.BlockUpdate(p, 0, p.Length);
            sm3c3.DoFinal(c3, 0);
            Reset();
        }
    }
}
