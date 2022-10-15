using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int GCD(int a , int b)
        {
            int temp;
            while(true)
            {
                temp = a % b;
                if (temp == 0)
                    return b;
                a = b;
                b = temp;

            }
        }
        public int getE(int p , int q)
        {
            int n = p * q;
            int e = 2;
            int Qn = (p - 1) * (q - 1);
            while(e<Qn)
            {
                if (GCD(e, Qn) == 1)
                    break;
                else
                    e++;
            }
            return e;
        }
        public static int fast_power(int x, int y, int p)
        {
            int res = 1;
            x = x % p; 
            if (x == 0)
                return 0;
            while (y > 0)
            {
                if ((y & 1) != 0)
                    res = (res * x) % p;               
                y = y >> 1; // y = y/2
                x = (x * x) % p;
            }
            return res;
        }   
        public int Encrypt(int p, int q, int M, int e)
        {
            //ans=(M^e)%(p*q) ,
            double ans = Math.Pow(M, e);
            int n = q * p;
            ans = ans % n;
            return (int)(ans);

            //int ans = fast_power(M, e, q * p);
            //return ans;
            throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            // ans=c^e mod(p*q)
            double ans = Math.Pow(C, e);
            int n = p * q;
            ans = ans % n;
            return (int)(ans);

            //int ans = fast_power(C, e, q * p);
            //return ans;
            throw new NotImplementedException();
        }
    }
}
