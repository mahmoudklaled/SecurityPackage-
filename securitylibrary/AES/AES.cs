using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 

    
    
    public class AES : CryptographicTechnique
    {
        //************************* Helper Function *******************************//
        
        public static string[,] convertStringToMatrixByColoum(string s)
        {
            string[,] stateMatrix = new string[4, 4];
            string temp = "00";
            char[] charArr = temp.ToCharArray();
            int n = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)

                {

                    charArr[0] = s[n];
                    charArr[1] = s[n + 1];
                    string tempStr = new string(charArr);
                    stateMatrix[j, i] = tempStr;
                    n += 2;
                }

            }

            return stateMatrix;
        }

        private static void get_indx_for_x_box(ref int i, ref int j, string s)
        {
            char a = s[0];
            char b = s[1];
            if (a >= '0' && a <= '9')
                i = (int)(a - '0');
            else
            {
                if (a == 'A' || a == 'a')
                    i = 10;
                if (a == 'B' || a == 'b')
                    i = 11;
                if (a == 'C' || a == 'c')
                    i = 12;
                if (a == 'D' || a == 'd')
                    i = 13;
                if (a == 'E' || a == 'e')
                    i = 14;
                if (a == 'F' || a == 'f')
                    i = 15;

            }

            if (b >= '0' && b <= '9')
                j = (int)(b - '0');
            else
            {
                if (b == 'A' || b == 'a')
                    j = 10;
                if (b == 'B' || b == 'b')
                    j = 11;
                if (b == 'C' || b == 'c')
                    j = 12;
                if (b == 'D' || b == 'd')
                    j = 13;
                if (b == 'E' || b == 'e')
                    j = 14;
                if (b == 'F' || b == 'f')
                    j = 15;

            }
        }
        public static string[,] GetS_Box_Value(string[,] s, string[,] sbox)
        {
            int valI = -1, valJ = -1;
            string[,] s_box = new string[s.GetLength(0), s.GetLength(1)];
            for (int i = 0; i < s.GetLength(0); i++)
            {
                for (int j = 0; j < s.GetLength(1); j++)
                {
                    get_indx_for_x_box(ref valI, ref valJ, s[i, j]);
                    s_box[i, j] = sbox[valI, valJ];
                }
            }
            return s_box;
        }

        public static string[,] ShiftRows(string[,] s)
        {
            string temp1 = s[1, 0];

            /* manual
            s[1, 0] = s[1, 1];
            s[1, 1] = s[1, 2];
            s[1, 2] = s[1, 3];
            s[1, 3] = temp1;
            */
            //shift 2nd row
            for (int i = 0; i < 3; i++)
                s[1, i] = s[1, i + 1];
            s[1, 3] = temp1;
            //2nd row done;
            //shift 3ed row
            string t1 = s[2, 0], t2 = s[2, 1], t3;
            s[2, 0] = s[2, 2];
            s[2, 1] = s[2, 3];
            s[2, 2] = t1;
            s[2, 3] = t2;
            //shift 3rd row
            t1 = s[3, 0];
            t2 = s[3, 1];
            t3 = s[3, 2];
            s[3, 0] = s[3, 3];
            s[3, 1] = t1;
            s[3, 2] = t2;
            s[3, 3] = t3;

            return s;
        }
        private static byte GMul(byte a, byte b)
        { // Galois Field (256) Multiplication of two Bytes
            byte p = 0;


            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hi_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }

            return p;
        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public static string ByteArrayToString(byte baa)
        {
            byte[] ba = new byte[1];
            ba[0] = baa;
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        private static string[,] MixColumns(string[,] plain)
        { // 's' is the main State matrix, 'ss' is a temp matrix of the same dimensions as 's'.
            byte[,] ss = new byte[4, 4];
            byte[,] s = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexString = plain[i, j];
                    byte[] floatVals = StringToByteArray(hexString);
                    s[i, j] = floatVals[0];

                }
            }

            string[,] ans = new string[4, 4];

            for (int c = 0; c < 4; c++)
            {
                ss[0, c] = (byte)(GMul(0x02, s[0, c]) ^ GMul(0x03, s[1, c]) ^ s[2, c] ^ s[3, c]);
                ss[1, c] = (byte)(s[0, c] ^ GMul(0x02, s[1, c]) ^ GMul(0x03, s[2, c]) ^ s[3, c]);
                ss[2, c] = (byte)(s[0, c] ^ s[1, c] ^ GMul(0x02, s[2, c]) ^ GMul(0x03, s[3, c]));
                ss[3, c] = (byte)(GMul(0x03, s[0, c]) ^ s[1, c] ^ s[2, c] ^ GMul(0x02, s[3, c]));

                ans[0, c] = ByteArrayToString(ss[0, c]);
                ans[1, c] = ByteArrayToString(ss[1, c]);
                ans[2, c] = ByteArrayToString(ss[2, c]);
                ans[3, c] = ByteArrayToString(ss[3, c]);
            }

            return ans;
        }
        public class HexString
        {
            private byte[] _data;

            public HexString(byte[] data)
            {
                _data = data;
            }

            public HexString(string data)
            {
                if ((data.Length & 1) != 0) throw new ArgumentException("Hex string must have an even number of digits.");

                _data = Enumerable.Range(0, data.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(data.Substring(x, 2), 16))
                    .ToArray();
            }
            public override string ToString()
            {
                string hex = BitConverter.ToString(_data);
                return hex.Replace("-", "");
            }
            static public HexString operator ^(HexString LHS, HexString RHS)
            {
                return new HexString
                    (
                        LHS._data.Zip
                            (
                                RHS._data,
                                (a, b) => (byte)(a ^ b)
                            )
                        .ToArray()
                    );
            }
        }
        public static string[,] AddRoundKey(string[,] p, string[,] key)
        {
            string[,] ans = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    HexString p1 = new HexString(p[i, j]);
                    HexString k1 = new HexString(key[i, j]);
                    HexString xorval = p1 ^ k1;
                    ans[i, j] = xorval.ToString();
                }
            }

            return ans;
        }
        //*******************Key schedule **************************//
        public static string[,] getCoulumForKey(string[,] s, int indx)
        {
            string[,] ans = new string[4, 1];
            ans[0, 0] = s[0, indx];
            ans[1, 0] = s[1, indx];
            ans[2, 0] = s[2, indx];
            ans[3, 0] = s[3, indx];
            return ans;
        }
        public static string[,] shitColoumn(string[,] s)
        {
            string temp = s[0, 0];
            s[0, 0] = s[1, 0];
            s[1, 0] = s[2, 0];
            s[2, 0] = s[3, 0];
            s[3, 0] = temp;

            return s;
        }
        public static string[,] xorthreecol(string[,] s1, string[,] s2, string[,] s3)
        {
            string[,] ans = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 1; j++)
                {
                    HexString p1 = new HexString(s1[i, j]);
                    HexString k1 = new HexString(s2[i, j]);
                    HexString c1 = new HexString(s3[i, j]);
                    HexString xorval = p1 ^ k1 ^ c1;
                    ans[i, j] = xorval.ToString().ToLower();
                }
            }

            return ans;
        }
        public static string[,] xortwocol(string[,] s1, string[,] s2)
        {
            string[,] ans = new string[s1.GetLength(0), s2.GetLength(1)];
            for (int i = 0; i < ans.GetLength(0); i++)
            {
                for (int j = 0; j < ans.GetLength(1); j++)
                {
                    HexString p1 = new HexString(s1[i, j]);
                    HexString k1 = new HexString(s2[i, j]);

                    HexString xorval = p1 ^ k1;
                    ans[i, j] = xorval.ToString().ToLower();
                }
            }

            return ans;
        }
        public static string[,] compinefourcol(string[,] s1, string[,] s2, string[,] s3, string[,] s4)
        {
            string[,] ans = new string[4, 4];
            ans[0, 0] = s1[0, 0];
            ans[1, 0] = s1[1, 0];
            ans[2, 0] = s1[2, 0];
            ans[3, 0] = s1[3, 0];


            ans[0, 1] = s2[0, 0];
            ans[1, 1] = s2[1, 0];
            ans[2, 1] = s2[2, 0];
            ans[3, 1] = s2[3, 0];


            ans[0, 2] = s3[0, 0];
            ans[1, 2] = s3[1, 0];
            ans[2, 2] = s3[2, 0];
            ans[3, 2] = s3[3, 0];


            ans[0, 3] = s4[0, 0];
            ans[1, 3] = s4[1, 0];
            ans[2, 3] = s4[2, 0];
            ans[3, 3] = s4[3, 0];

            return ans;
        }
        public static string[,] generateRoundKey(string[,] Key, string[,] rcon, int round_N, string[,] s_box)
        {
            //step 1 take last col.
            string[,] last_col = getCoulumForKey(Key, 3);

            //step 2 do shift col.
            string[,] shifted_col = shitColoumn(last_col);

            // step 3 replace with get s_box
            string[,] replaced_with_sbox_value = GetS_Box_Value(shifted_col, s_box);

            //step 4 xor with rcon and xor with first_col. and with replaced with s box
            string[,] first_key_col = getCoulumForKey(Key, 0);

            string[,] rcon_col = getCoulumForKey(rcon, round_N);

            string[,] firstxor = xorthreecol(first_key_col, replaced_with_sbox_value, rcon_col);

            string[,] secndxor = xortwocol(getCoulumForKey(Key, 1), firstxor);

            string[,] thirdxor = xortwocol(getCoulumForKey(Key, 2), secndxor);

            string[,] forthxor = xortwocol(getCoulumForKey(Key, 3), thirdxor);

            string[,] ans = compinefourcol(firstxor, secndxor, thirdxor, forthxor);


            return ans;
        }
        //********************Decrept helpers *****************************************//
        public static string[,] inverseShiftRows(string[,] s)
        {
            string temp1 = s[1, 3];

            // manual
            s[1, 3] = s[1, 2];
            s[1, 2] = s[1, 1];
            s[1, 1] = s[1, 0];
            s[1, 0] = temp1;
            
            //shift 2nd row
            
            //2nd row done;
            //shift 3ed row
            string t1 = s[2, 3], t2 = s[2, 2], t3 , t4;
            s[2, 3] = s[2, 1];
            s[2, 2] = s[2, 0];
            s[2, 1] = t1;
            s[2, 0] = t2;
            //shift 3rd row
            t4 = s[3, 0]; t1 = s[3, 1]; t2 = s[3, 2]; t3 = s[3, 3];
            s[3, 0] = t1;
            s[3, 1] = t2;
            s[3, 2] = t3;
            s[3, 3] = t4;

            return s;
        }
        private static string[,] InverseMixColumns(string[,] plain)
        { // 's' is the main State matrix, 'ss' is a temp matrix of the same dimensions as 's'.
            byte[,] ss = new byte[4, 4];
            byte[,] s = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexString = plain[i, j];
                    byte[] floatVals = StringToByteArray(hexString);
                    s[i, j] = floatVals[0];

                }
            }

            string[,] ans = new string[4, 4];

            for (int c = 0; c < 4; c++)
            {
                ss[0, c] = (byte)(GMul(0x0e, s[0, c]) ^ GMul(0x0b, s[1, c]) ^ GMul(0x0d, s[2, c]) ^ GMul(0x09, s[3, c]));
                ss[1, c] = (byte)(GMul(0x09, s[0, c]) ^ GMul(0x0e, s[1, c]) ^ GMul(0x0b, s[2, c]) ^ GMul(0x0d, s[3, c]));
                ss[2, c] = (byte)(GMul(0x0d, s[0, c]) ^ GMul(0x09, s[1, c]) ^ GMul(0x0e, s[2, c]) ^ GMul(0x0b, s[3, c]));
                ss[3, c] = (byte)(GMul(0x0b, s[0, c]) ^ GMul(0x0d, s[1, c]) ^ GMul(0x09, s[2, c]) ^ GMul(0x0e, s[3, c]));

                ans[0, c] = ByteArrayToString(ss[0, c]);
                ans[1, c] = ByteArrayToString(ss[1, c]);
                ans[2, c] = ByteArrayToString(ss[2, c]);
                ans[3, c] = ByteArrayToString(ss[3, c]);
            }

            return ans;
        }

        //*************************************************************************//

        public override string Decrypt(string cipherText, string key)
        {
            int number_of_iterate = (cipherText.Length - 2) / 32, start_indx = 2, siz = 32;
            string ans = "0x";
            string[,] s_box = new string[16, 16]
{
                {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
                {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
                {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
                {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
                {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
                {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
                {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
                {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
                {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
                {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
                {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
                {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
                {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
                {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
                {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
                {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
};
            string[,] inversr_s_box = new string[16, 16]
            {

                {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
                {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
                {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
                {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
                {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
                {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
                {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
                {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
                {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
                {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
                {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
                {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
                {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
                {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
                {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
                {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21" ,"0c", "7d"}
            };
            string[,] c_Rcon = new string[4, 10]
            {
                {"01" , "02",  "04",  "08",  "10",  "20" , "40",  "80",  "1b",  "36" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" }
            };
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            for (int gg = 0; gg < number_of_iterate; gg++, start_indx += siz)
            {
                string mainPlain = cipherText.Substring(start_indx, siz);
                string mainKey = key.Substring(2, 32);
                string[,] stateMatrix = convertStringToMatrixByColoum(mainPlain);
                string[,] KeyMatrix = convertStringToMatrixByColoum(mainKey);
                string[,] AfterSubByte = new string[4, 4];
                string[,] afterRoundKey = new string[4, 4];
                string[,] AfterInverseShiftRow = new string[4, 4];
                string[,] AfterInverseMixColoumn = new string[4, 4];
                //get all key exaption
                string[,] Key1 = generateRoundKey(KeyMatrix, c_Rcon, 0, s_box);
                string[,] Key2 = generateRoundKey(Key1, c_Rcon, 1, s_box);
                string[,] Key3 = generateRoundKey(Key2, c_Rcon, 2, s_box);
                string[,] Key4 = generateRoundKey(Key3, c_Rcon, 3, s_box);
                string[,] Key5 = generateRoundKey(Key4, c_Rcon, 4, s_box);
                string[,] Key6 = generateRoundKey(Key5, c_Rcon, 5, s_box);
                string[,] Key7 = generateRoundKey(Key6, c_Rcon, 6, s_box);
                string[,] Key8 = generateRoundKey(Key7, c_Rcon, 7, s_box);
                string[,] Key9 = generateRoundKey(Key8, c_Rcon, 8, s_box);
                string[,] Key10 = generateRoundKey(Key9, c_Rcon, 9, s_box);
                List<string[,]> allKeys = new List<string[,]>();
                allKeys.Add(Key10);
                allKeys.Add(Key9);
                allKeys.Add(Key8);
                allKeys.Add(Key7);
                allKeys.Add(Key6);
                allKeys.Add(Key5);
                allKeys.Add(Key4);
                allKeys.Add(Key3);
                allKeys.Add(Key2);
                allKeys.Add(Key1);
                allKeys.Add(KeyMatrix);

                //***************************************************************//

                afterRoundKey = xortwocol(stateMatrix, allKeys[0]);


                AfterInverseShiftRow = inverseShiftRows(afterRoundKey);
                AfterSubByte = GetS_Box_Value(AfterInverseShiftRow, inversr_s_box);
                afterRoundKey = AddRoundKey(AfterSubByte, KeyMatrix);

                afterRoundKey = AddRoundKey(AfterSubByte, allKeys[1]);

                for (int i = 0; i < 9; i++)
                {

                    AfterInverseMixColoumn = InverseMixColumns(afterRoundKey);
                    AfterInverseShiftRow = inverseShiftRows(AfterInverseMixColoumn);
                    AfterSubByte = GetS_Box_Value(AfterInverseShiftRow, inversr_s_box);
                    afterRoundKey = xortwocol(AfterSubByte, allKeys[i + 2]);
                }
                
                for (int i = 0; i < afterRoundKey.GetLength(1); i++)
                {
                    ans += afterRoundKey[0, i];
                    ans += afterRoundKey[1, i];
                    ans += afterRoundKey[2, i];
                    ans += afterRoundKey[3, i];
                }
            }
            return ans;
            

            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            int number_of_iterate = (plainText.Length-2) / 32 , start_indx=2,siz=32;
            string ans = "0x";
            string[,] s_box = new string[16, 16]
            {
                {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
                {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
                {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
                {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
                {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
                {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
                {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
                {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
                {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
                {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
                {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
                {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
                {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
                {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
                {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
                {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
            };
            string[,] c_Rcon = new string[4, 10]
            {
                {"01" , "02",  "04",  "08",  "10",  "20" , "40",  "80",  "1b",  "36" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" },
                {"00" , "00",  "00",  "00",  "00",  "00" , "00",  "00",  "00",  "00" }
            };
            plainText = plainText.ToLower();
            key = key.ToLower();
            for (int uuu = 0; uuu < number_of_iterate; uuu++,start_indx+=siz)
            {
                string mainPlain = plainText.Substring(start_indx, siz);
                string mainKey = key.Substring(2, siz);

                string[,] stateMatrix = convertStringToMatrixByColoum(mainPlain);
                string[,] KeyMatrix = convertStringToMatrixByColoum(mainKey);

                //first xor 
                string[,] stateOfRound = xortwocol(stateMatrix, KeyMatrix);
                string[,] AfterSubByte = new string[4, 4];
                string[,] AfterShifRows = new string[4, 4];
                string[,] AfterMixColumns = new string[4, 4];
                for (int c = 0; c < 9; c++)
                {
                    AfterSubByte = GetS_Box_Value(stateOfRound, s_box);
                    AfterShifRows = ShiftRows(AfterSubByte);
                    AfterMixColumns = MixColumns(AfterShifRows);
                    KeyMatrix = generateRoundKey(KeyMatrix, c_Rcon, c, s_box);
                    stateOfRound = xortwocol(AfterMixColumns, KeyMatrix);

                }
                AfterSubByte = GetS_Box_Value(stateOfRound, s_box);
                AfterShifRows = ShiftRows(AfterSubByte);
                KeyMatrix = generateRoundKey(KeyMatrix, c_Rcon, 9, s_box);
                stateOfRound = xortwocol(AfterShifRows, KeyMatrix);

                
                for (int i = 0; i < stateOfRound.GetLength(1); i++)
                {
                    ans += stateOfRound[0, i];
                    ans += stateOfRound[1, i];
                    ans += stateOfRound[2, i];
                    ans += stateOfRound[3, i];
                }
            }
            return ans;

            throw new NotImplementedException();
        }
    }
}


