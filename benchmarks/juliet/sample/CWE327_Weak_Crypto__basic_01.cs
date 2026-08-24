/* Juliet-shaped sample (not from the real suite). */
using System.Security.Cryptography;

namespace crit.benchmark
{
    class CWE327_Weak_Crypto__basic_01
    {
        public void Bad()
        {
            /* POTENTIAL FLAW: broken hash */
            var h = MD5.Create();
            h.ComputeHash(new byte[0]);
        }

        public void GoodG2B()
        {
            /* FIX: strong hash */
            var h = SHA256.Create();
            h.ComputeHash(new byte[0]);
        }
    }
}
