using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            Dictionary<Char, Char> mp = new Dictionary<char, char>();
            char xx = 'a';
            char val = 'A';
            for (int i = 0; i < 26; i++)
            {

                mp[xx] = val;
                val++;
                xx++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                mp[plainText[i]] = cipherText[i];
            }
            string str = "";

            var list = mp.Keys.ToList();
            list.Sort();

            foreach (var key in list)
            {
                str += mp[key];
            }
            return str;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string str = "";
            char x = 'a';
            cipherText = cipherText.ToLower();
            Dictionary<Char, Char> mp = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                mp.Add(key[i], x);
                //Console.Write(x);
                x++;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                char val = cipherText[i];
                str += mp[val];
            }
            return str;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string str = "";
            char x = 'a';
            Dictionary<Char, Char> mp = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                mp.Add(x, key[i]);
                x++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                char val = plainText[i];
                str += mp[val];
            }
            return str;
            //throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string str = "";
            Dictionary<int, char> mp = new Dictionary<int, char>();
            mp.Add(1, 'E');
            mp.Add(2, 'T');
            mp.Add(3, 'A');
            mp.Add(4, 'O');
            mp.Add(5, 'I');
            mp.Add(6, 'N');
            mp.Add(7, 'S');
            mp.Add(8, 'R');
            mp.Add(9, 'H');
            mp.Add(10, 'L');
            mp.Add(11, 'D');
            mp.Add(12, 'C');
            mp.Add(13, 'U');
            mp.Add(14, 'M');
            mp.Add(15, 'F');
            mp.Add(16, 'P');
            mp.Add(17, 'G');
            mp.Add(18, 'W');
            mp.Add(19, 'Y');
            mp.Add(20, 'B');
            mp.Add(21, 'V');
            mp.Add(22, 'K');
            mp.Add(23, 'X');
            mp.Add(24, 'J');
            mp.Add(25, 'Q');
            mp.Add(26, 'Z');
            Dictionary<Char, int> count_mp = new Dictionary<char, int>();
            for (char a = 'A'; a <= 'Z'; a++)
            {
                count_mp.Add(a, 0);
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                count_mp[cipher[i]]++;
            }

            var items = from pair in count_mp
                        orderby pair.Value descending
                        select pair;
            int n = 1;
            Dictionary<char, char> keyMap = new Dictionary<char, char>();
            // keymap key=> chiper, value=> main cahr 
            foreach (KeyValuePair<char, int> pair in items)
            {
                keyMap.Add(pair.Key, mp[n]);
                n++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                str += keyMap[cipher[i]];
            }
            return str;
            //throw new NotImplementedException();
        }
    }
}
