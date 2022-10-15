using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int a1 = 1, a2 = 0, a3 = baseN;
            int b1 = 0, b2 = 1, b3 = number;
            int q= -1;
            int t1, t2, t3;
            while(true)
            {
                if (b3 == 0)
                    return -1;
                if (b3 == 1)
                    return (b2 + baseN) % baseN;
                q = a3 / b3;
                t1 = a1 - q * b1;
                t2 = a2 - q * b2;
                t3 = a3 - q * b3;

                a1 = b1;a2 = b2;a3 = b3;
                b1 = t1;b2 = t2;b3 = t3;
            }
            throw new NotImplementedException();
        }
    }
}
