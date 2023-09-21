using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arric.Crypto.SM.SM4
{
    /// <summary>
    /// SM4处理中心
    /// </summary>
    internal class Sm4Context
    {
        public Sm4Context()
        {
            Mode = 1;
            IsPadding = true;
            Key = new long[32];
        }

        /// <summary>
        /// 1表示加密，0表示解密
        /// </summary>
        public int Mode;

        /// <summary>
        /// 密钥
        /// </summary>
        public long[] Key;

        /// <summary>
        /// 是否补足16进制字符串
        /// </summary>
        public bool IsPadding;
    }
}
