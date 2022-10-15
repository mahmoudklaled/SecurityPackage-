using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    /// 

    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {

        // **************************************** HELPER FUNCTINOS **************************************** //
        public static List<int> generateKeyInverseMatrixByRef(int[,] key, int b, ref int[,] inverse)
        {

            // calculate rule K(i,j)
            int k = 0, det = 0;
            List<int> vals = new List<int>();

            int[,] inversekeyMatrix = new int[key.GetLength(0), key.GetLength(1)];

            if (key.GetLength(0) == 2)
            {
                int tmp = key[0, 0];
                key[0, 0] = key[1, 1];
                key[1, 1] = tmp;

                key[0, 1] *= -1;
                key[1, 0] *= -1;

                inversekeyMatrix = key;

                tmp = 0;
                for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
                {
                    for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                    {
                        tmp = (b * inversekeyMatrix[r, c]) % 26;
                        if (tmp < 0)
                        {
                            tmp += 26;
                        }
                        vals.Add(tmp);
                    }
                }
                int valsIndexer = 0;
                for (int r = 0; r < key.GetLength(0); r++)
                    for (int c = 0; c < key.GetLength(1); c++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];

            }

            else
            {
                for (int r = 0; r < key.GetLength(0); r++)
                {
                    for (int c = 0; c < key.GetLength(1); c++)
                    {

                        if (key.GetLength(0) == 2)
                        {
                            det = calcDet(key);
                        }
                        else
                        {
                            det = calcDet(generateSubMatrix(key, r, c));
                        }

                        k = (b * (int)Math.Pow(-1, r + c) * det) % 26;

                        if (k < 0)
                        {
                            k += 26;
                        }
                        vals.Add(k);
                    }
                }

                //generate key inverse matrix
                int valsIndexer = 0;
                for (int c = 0; c < key.GetLength(1); c++)
                    for (int r = 0; r < key.GetLength(0); r++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];

            }
            inverse = inversekeyMatrix;

            List<int> inverseKeyList = new List<int>();
            for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
            {
                for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                {
                    inverseKeyList.Add(inversekeyMatrix[r, c]);
                }
            }



            return inverseKeyList;
        }
        public static int[,] generateKeyMatrixfor3by3anlasis(List<int> key, int rowsNumber)
        {
            int colsNumber = key.Count / rowsNumber;
            int[,] keyMatrix = new int[rowsNumber, colsNumber];
            for (int i = 0, j = 0; i < key.Count; i += 3, j++)
            {
                if (i == key.Count - 1)
                    break;
                keyMatrix[0, j] = key[i];
                keyMatrix[1, j] = key[i + 1];
                keyMatrix[2, j] = key[i + 2];

            }


            return keyMatrix;
        }

        public static int GCD(int a, int b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a | b;
        }

        public static int[,] generateKeyMatrix(List<int> key, int rowsNumber)
        {
            int colsNumber = key.Count / rowsNumber;
            int[,] keyMatrix = new int[rowsNumber, colsNumber];

            int i = 0;
            for (int r = 0; r < rowsNumber; r++)
                for (int c = 0; c < colsNumber; c++)
                    keyMatrix[r, c] = key[i++];

            return keyMatrix;
        }

        public static int[,] generateSubMatrix(int[,] key, int row, int col)
        {
            // allocate submatrix with size of the original matrix less by one row and one column
            int[,] subMatrix = new int[key.GetLength(0) - 1, key.GetLength(1) - 1];

            List<int> numsToTake = new List<int>();

            for (int r = 0; r < key.GetLength(0); r++)
            {
                for (int c = 0; c < key.GetLength(1); c++)
                {
                    if (r == row || c == col)
                        continue;

                    numsToTake.Add(key[r, c]);
                }
            }

            subMatrix = generateKeyMatrix(numsToTake, (int)Math.Sqrt(numsToTake.Count));
            return subMatrix;
        }

        public static int calcDet(int[,] key)
        {
            int det;
            int size = key.GetLength(0);
            if (size == 2)
            {
                det = key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0];
            }
            else
            {
                det = key[0, 0] * ((key[1, 1] * key[2, 2]) - (key[1, 2] * key[2, 1])) -
                       key[0, 1] * ((key[1, 0] * key[2, 2]) - (key[1, 2] * key[2, 0])) +
                       key[0, 2] * ((key[1, 0] * key[2, 1]) - (key[1, 1] * key[2, 0]));
            }
            if (det % 26 < 0)
            {
                det %= 26;
                det += 26;
                return det;
            }

            return det % 26;
        }

        public static int calcB(int det)
        {
            for (int i = 1; i < 26; i++)
                if ((i * det) % 26 == 1)
                    return i;

            return -1;
        }

        public static List<int> generateKeyInverseMatrix(int[,] key, int b)
        {

            // calculate rule K(i,j)
            int k = 0, det = 0;
            List<int> vals = new List<int>();

            int[,] inversekeyMatrix = new int[key.GetLength(0), key.GetLength(1)];

            if (key.GetLength(0) == 2)
            {
                int tmp = key[0, 0];
                key[0, 0] = key[1, 1];
                key[1, 1] = tmp;

                key[0, 1] *= -1;
                key[1, 0] *= -1;

                inversekeyMatrix = key;

                tmp = 0;
                for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
                {
                    for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                    {
                        tmp = (b * inversekeyMatrix[r, c]) % 26;
                        if (tmp < 0)
                        {
                            tmp += 26;
                        }
                        vals.Add(tmp);
                    }
                }
                int valsIndexer = 0;
                for (int r = 0; r < key.GetLength(0); r++)
                    for (int c = 0; c < key.GetLength(1); c++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];

            }

            else
            {
                for (int r = 0; r < key.GetLength(0); r++)
                {
                    for (int c = 0; c < key.GetLength(1); c++)
                    {

                        if (key.GetLength(0) == 2)
                        {
                            det = calcDet(key);
                        }
                        else
                        {
                            det = calcDet(generateSubMatrix(key, r, c));
                        }

                        k = (b * (int)Math.Pow(-1, r + c) * det) % 26;

                        if (k < 0)
                        {
                            k += 26;
                        }
                        vals.Add(k);
                    }
                }

                //generate key inverse matrix
                int valsIndexer = 0;
                for (int c = 0; c < key.GetLength(1); c++)
                    for (int r = 0; r < key.GetLength(0); r++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];

            }

            List<int> inverseKeyList = new List<int>();
            for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
            {
                for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                {
                    inverseKeyList.Add(inversekeyMatrix[r, c]);
                }
            }



            return inverseKeyList;
        }

        public static List<int> GetOcurrance(List<int> Plain, List<int> chifer, List<int> key)
        {

            List<int> ans = new List<int>();
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < Plain.Count; j++)
                {
                    if (key[i] == Plain[j])
                    {
                        ans.Add(chifer[j]);
                        break;
                    }
                }
            }
            return ans;
        }
        public static bool hasInverse(int[,] keyMatrix, int det, int b)
        {
            bool nonnegative = true;
            bool hasGCD = true;
            bool hasB = true;
            bool det_not_zero = true;

            //1- check if all elements are nonnegative and less than 26
            for (int r = 0; r < keyMatrix.GetLength(0); r++)
            {
                for (int c = 0; c < keyMatrix.GetLength(1); c++)
                {
                    if (keyMatrix[r, c] < 0 || keyMatrix[r, c] > 26)
                    {
                        nonnegative = false;
                        break;
                    }
                }
                if (nonnegative == false)
                    break;
            }

            //2- check for GCD 
            if (GCD(det, 26) != 1)
                hasGCD = false;

            //3- check for b
            if (b > 26 || (b * det) % 26 != 1)
                hasB = false;


            //4- check if det != 0
            if (det == 0)
                det_not_zero = false;


            if (nonnegative && hasGCD && hasB && det_not_zero)
                return true;

            return false;
        }

        public static int[,] MultiplyMatrix(int[,] A, int[,] B)
        {
            int rA = A.GetLength(0);
            int cA = A.GetLength(1);
            int rB = B.GetLength(0);
            int cB = B.GetLength(1);
            int temp = 0;
            int[,] kHasil = new int[rA, cB];
            if (cA != rB)
            {
                Console.WriteLine("matrik can't be multiplied !!");
                return null;
            }
            else
            {
                for (int i = 0; i < rA; i++)
                {
                    for (int j = 0; j < cB; j++)
                    {
                        temp = 0;
                        for (int k = 0; k < cA; k++)
                        {
                            temp += A[i, k] * B[k, j];
                        }
                        kHasil[i, j] = temp;
                    }
                }
                return kHasil;
            }
        }
        // **************************************** HELPER FUNCTINOS **************************************** //



        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();

            List<int> plain = plainText;
            List<int> cipher = cipherText;
            List<int> keyInverseMatrix = new List<int>();
            List<int> needed_key = new List<int>();
            bool key_find = false;
            int det = -9999, ii = -1, jj = -1;
            int[,] keyMatrix = null;
            int[,] Key4by4 = null;
            List<int> test4 = new List<int>();
            keyMatrix = new int[2, plain.Count / 2];
            for (int i = 0; i < plain.Count / 2; i += 2)
            {
                keyMatrix[0, i] = plain[i];
                keyMatrix[1, i] = plain[i + 1];
            }
            for (int i = 0; i < plain.Count / 2; i++)
            {
                for (int j = i + 1; j < plain.Count / 2; j++)
                {
                    test4.Add(keyMatrix[0, i]);
                    test4.Add(keyMatrix[0, j]);
                    test4.Add(keyMatrix[1, i]);
                    test4.Add(keyMatrix[1, j]);
                    int[,] test_keyMatrix = generateKeyMatrix(test4, 2);
                    int test_det = calcDet(test_keyMatrix);
                    if (GCD(test_det, 26) == 1)
                    {
                        needed_key = test4;
                        key_find = true;
                        det = test_det;
                        keyMatrix = test_keyMatrix;
                        Key4by4 = test_keyMatrix;
                        ii = i;
                        jj = j;
                        break;
                    }
                    test4.Clear();

                }
                if (key_find)
                    break;
            }

            if (key_find == false)
            {
                throw new InvalidAnlysisException();
            }

            int b = calcB(det);

            int[,] inverse_Matrix = null;
            generateKeyInverseMatrixByRef(keyMatrix, b, ref inverse_Matrix);
            List<int> answer = new List<int>();
            int[,] Equavilant_ciper = new int[2, cipher.Count / 2];
            for (int i = 0; i < cipher.Count / 2; i += 2)
            {
                Equavilant_ciper[0, i] = cipher[i];
                Equavilant_ciper[1, i] = cipher[i + 1];
            }
            int[,] Equavilant_ciper2by2 = new int[2, 2];
            Equavilant_ciper2by2[0, 0] = Equavilant_ciper[0, ii];
            Equavilant_ciper2by2[1, 0] = Equavilant_ciper[1, ii];
            Equavilant_ciper2by2[0, 1] = Equavilant_ciper[0, jj];
            Equavilant_ciper2by2[1, 1] = Equavilant_ciper[1, jj];
            int[,] mat1 = Equavilant_ciper2by2;
            int[,] mat2 = inverse_Matrix;

            int[,] ansMat = MultiplyMatrix(mat1, mat2);

            answer.Add(ansMat[0, 0] % 26);
            answer.Add(ansMat[0, 1] % 26);
            answer.Add(ansMat[1, 0] % 26);
            answer.Add(ansMat[1, 1] % 26);

            return answer;

        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = generateKeyMatrix(key, m);

            int det = calcDet(keyMatrix);
            int b = calcB(det);
            if (!hasInverse(keyMatrix, det, b))
                throw new InvalidAnlysisException();
            List<int> keyInverseMatrix = generateKeyInverseMatrix(keyMatrix, b);

            List<int> answer = Encrypt(cipherText, keyInverseMatrix);

            return answer;
            //throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int sz = 0;
            if (key.Count == 4)
                sz = 2;
            else
                sz = 3;
            List<int> answer = new List<int>();
            if (sz == 2)
            {
                int indx = 0;
                for (int i = 0; i < plainText.Count; i += 2, indx += 2)
                {
                    int val1 = plainText[indx], val2 = plainText[indx + 1];

                    int final1 = 0, final2 = 0;
                    final1 = ((key[0] * val1) + (key[1] * val2)) % 26;
                    final2 = ((key[2] * val1) + (key[3] * val2)) % 26;
                    answer.Add(final1);
                    answer.Add(final2);

                }
            }
            if (sz == 3)
            {
                int indx = 0;
                for (int i = 0; i < plainText.Count; i += 3, indx += 3)
                {
                    int val1 = plainText[i], val2 = plainText[i + 1], val3 = plainText[i + 2];
                    int final1 = 0, final2 = 0, final3 = 0;
                    final1 = ((key[0] * val1) + (key[1] * val2) + (key[2] * val3)) % 26;
                    final2 = ((key[3] * val1) + (key[4] * val2) + (key[5] * val3)) % 26;
                    final3 = ((key[6] * val1) + (key[7] * val2) + (key[8] * val3)) % 26;
                    answer.Add(final1);
                    answer.Add(final2);
                    answer.Add(final3);
                }
            }
            return answer;

        }



        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> plain = plainText;
            List<int> cipher = cipherText;
            List<int> keyInverseMatrix = new List<int>();
            List<int> needed_key = new List<int>();
            bool key_find = false;
            int det = -9999;
            int[,] keyMatrix = null;
            int ii = -1, jj = -1, kk = -1;
            List<int> test9 = new List<int>();
            keyMatrix = new int[3, plain.Count / 3];
            for (int i = 0, j = 0; i < plain.Count; i += 3, j++)
            {
                if (i == plain.Count - 1)
                    break;
                keyMatrix[0, j] = plain[i];
                keyMatrix[1, j] = plain[i + 1];
                keyMatrix[2, j] = plain[i + 2];

            }

            for (int i = 0; i < plain.Count / 3; i++)
            {


                for (int j = i + 1; j < plain.Count / 3; j++)
                {
                    for (int k = j + 1; k < plain.Count / 3; k++)
                    {

                        test9.Add(keyMatrix[0, i]);
                        test9.Add(keyMatrix[0, j]);
                        test9.Add(keyMatrix[0, k]);

                        test9.Add(keyMatrix[1, i]);
                        test9.Add(keyMatrix[1, j]);
                        test9.Add(keyMatrix[1, k]);

                        test9.Add(keyMatrix[2, i]);
                        test9.Add(keyMatrix[2, j]);
                        test9.Add(keyMatrix[2, k]);


                        int[,] test_keyMatrix = generateKeyMatrix(test9, 3);
                        int test_det = calcDet(test_keyMatrix);
                        if (GCD(test_det, 26) == 1)
                        {
                            key_find = true;
                            det = test_det;
                            keyMatrix = test_keyMatrix;
                            ii = i;
                            jj = j;
                            kk = k;
                            break;
                        }

                        test9.Clear();
                    }
                    if (key_find)
                        break;

                }
                if (key_find)
                    break;
            }

            if (key_find == false || det == -9999)
            {
                throw new InvalidAnlysisException();
            }
            int b = calcB(det);
            int[,] inverseMatrixFinal = null;
            keyInverseMatrix = generateKeyInverseMatrixByRef(keyMatrix, b, ref inverseMatrixFinal);
            List<int> answer = new List<int>();
            int[,] convertCiper3by3_col = generateKeyMatrixfor3by3anlasis(cipher, 3);
            int[,] equvallent_mat = new int[3, 3];
            equvallent_mat[0, 0] = convertCiper3by3_col[0, ii];
            equvallent_mat[1, 0] = convertCiper3by3_col[1, ii];
            equvallent_mat[2, 0] = convertCiper3by3_col[2, ii];

            equvallent_mat[0, 1] = convertCiper3by3_col[0, jj];
            equvallent_mat[1, 1] = convertCiper3by3_col[1, jj];
            equvallent_mat[2, 1] = convertCiper3by3_col[2, jj];

            equvallent_mat[0, 2] = convertCiper3by3_col[0, kk];
            equvallent_mat[1, 2] = convertCiper3by3_col[1, kk];
            equvallent_mat[2, 2] = convertCiper3by3_col[2, kk];

            int[,] mat1 = equvallent_mat;
            int[,] mat2 = inverseMatrixFinal;

            int[,] ansMat = MultiplyMatrix(mat1, mat2);
            answer.Add(ansMat[0, 0] % 26);
            answer.Add(ansMat[0, 1] % 26);
            answer.Add(ansMat[0, 2] % 26);

            answer.Add(ansMat[1, 0] % 26);
            answer.Add(ansMat[1, 1] % 26);
            answer.Add(ansMat[1, 2] % 26);

            answer.Add(ansMat[2, 0] % 26);
            answer.Add(ansMat[2, 1] % 26);
            answer.Add(ansMat[2, 2] % 26);

            return answer;
        }

    }
}
