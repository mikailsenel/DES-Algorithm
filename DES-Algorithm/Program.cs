using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace DES_Algorithm
{
    class Program
    {
        

        static void Main(string[] args)
        {
            Program program = new Program();

            int[] M = new int[64]
            {
                0, 0, 0, 0,
                0, 0, 0, 1,
                0, 0, 1, 0,
                0, 0, 1, 1,
                0, 1, 0, 0,
                0, 1, 0, 1,
                0, 1, 1, 0,
                0, 1, 1, 1,
                1, 0, 0, 0,
                1, 0, 0, 1,
                1, 0, 1, 0,
                1, 0, 1, 1,
                1, 1, 0, 0,
                1, 1, 0, 1,
                1, 1, 1, 0,
                1, 1, 1, 1
            };      // plainText
            int[] KOriginal = new int[64]
            {
                0,0,0,1,
                0,0,1,1,
                0,0,1,1,
                0,1,0,0,
                0,1,0,1,
                0,1,1,1,
                0,1,1,1,
                1,0,0,1,
                1,0,0,1,
                1,0,1,1,
                1,0,1,1,
                1,1,0,0,
                1,1,0,1,
                1,1,1,1,
                1,1,1,1,
                0,0,0,1
            };              // Original key

            #region Şifreleme

            
            Console.WriteLine("Şifresiz Metin");
            for (int k = 0; k < M.Length; k++)
            {
                Console.Write(M[k]);
            }

            int[,] roundKeys = program.EncodingKeys(KOriginal);
            int[] cipherText=program.Encoding(M, roundKeys);

            Console.WriteLine();
            Console.WriteLine("Şifreli Metin");
            for (int k = 0; k < cipherText.Length; k++)
            {
                Console.Write(cipherText[k]);
            }
            #endregion

            #region Şifre çözme

            int[,] keys=program.EncodingKeys(KOriginal);
            int[] endKey=new int[56];
            for (int i = 0; i < 56; i++)
            {
                endKey[i] = keys[15, i];
            }

            int[,] decodeKeys=program.DecodingKeys(endKey);
            int[] pText = program.Encoding(cipherText, decodeKeys);

            Console.WriteLine();
            Console.WriteLine("Şifresiz Çözülen Metin");
            for (int k = 0; k < pText.Length; k++)
            {
                Console.Write(pText[k]);
            }
            #endregion
            Console.Read();
        }

        public int[,] DecodingKeys(int[] keys)
        {
            int[] K = keys;  // Key permutation

            int[] C = ArrayDivede(K, 0, K.Length / 2);         // Key Left
            int[] D = ArrayDivede(K, K.Length / 2, K.Length); // Key Right

            int[,] Ci = new int[16, 28];                        //Round Left Key
            int[,] Di = new int[16, 28];                        //Round Left Key
            for (int i = 0; i < 16; i++)
            {
                if (i != 0)
                {
                    C = KeyRightRotate(C, i);
                    D = KeyRightRotate(D, i);
                }
                for (int j = 0; j < 28; j++)
                {
                    Ci[i, j] = C[j];
                    Di[i, j] = D[j];
                }
            }

            int[,] keyMerges = KeyMerge(Ci, Di);

            return keyMerges;
        }

        public int[] Encoding(int[] M,int[,] roundKeys)
        {
           
            int[,] keys = RoundKey(roundKeys);
            return DataEncoding(keys, M);
        }

        public int[] DataEncoding(int[,] keys,int[] M)
        {
            #region Datanın şifrelenmesi

            int[] IP = Permutation(M, Const.IP);
            int[] L = null, R = null, temp;
            int[] key = new int[48];
            for (int i = 0; i < 17; i++)
            {
                if (i == 0)
                {
                    L = ArrayDivede(IP, 0, IP.Length / 2);
                    R = ArrayDivede(IP, IP.Length / 2, IP.Length);
                }
                else
                {
                    temp = L;
                    L = R;
                    for (int j = 0; j < 48; j++)
                    {
                        key[j] = keys[i - 1, j];
                    }

                    int[] f = FunctionF(R, key);
                    R = XOR(f, temp);
                }
            }
            
            temp = L;
            L = R;
            R = temp;
            List<int> tempList = new List<int>();
            foreach (int item in L)
            {
                tempList.Add(item);
            }

            foreach (int item in R)
            {
                tempList.Add(item);
            }

            int[] mergedLeftRight = tempList.ToArray();


            int[] cipherText = Permutation(mergedLeftRight, Const.IPINV);
            return cipherText;
            #endregion
        }

        public int[,] EncodingKeys(int[] key)
        {
            int[] K = Permutation(key, Const.PC1);  // Key permutation

            int[] C = ArrayDivede(K, 0, K.Length / 2);         // Key Left
            int[] D = ArrayDivede(K, K.Length / 2, K.Length); // Key Right

            int[,] Ci = new int[16, 28];                        //Round Left Key
            int[,] Di = new int[16, 28];                        //Round Left Key
            for (int i = 0; i < 16; i++)
            {
                
                    C = KeyLeftRotate(C, i);
                    D = KeyLeftRotate(D, i);
                
                for (int j = 0; j < 28; j++)
                {
                    Ci[i, j] = C[j];
                    Di[i, j] = D[j];
                }
            }

            int[,] keyMerges = KeyMerge(Ci, Di);
            
            return keyMerges;
        }

        public int[] Permutation(int[] array, int[] permutationArray)
        {
            int[] newArray = new int[permutationArray.Length];
            for (int i = 0; i < permutationArray.Length; i++)
            {
                newArray[i] = array[permutationArray[i] - 1];
            }

            return newArray;
        }

        public int[] ArrayDivede(int[] array, int start, int end)
        {
            int[] newArray = new int[end - start];
            for (int i = 0; i < newArray.Length; i++)
            {
                newArray[i] = array[start + i];
            }

            return newArray;
        }

        public int[] KeyLeftRotate(int[] array, int i)
        {
            int leftCount = Const.LeftShifts[i ];
            if (leftCount == 1)
            {
                int[] newArray = array;

                int temp = newArray[0];
                for (int j = 1; j < array.Length; j++)
                {
                    newArray[j-1] = newArray[j];
                }

                newArray[newArray.Length-1] = temp;

                return newArray;
            }
            else
            {
                int[] newArray = array;

                int temp = newArray[0];
                for (int j = 1; j < array.Length; j++)
                {
                    newArray[j - 1] = newArray[j];
                }

                newArray[newArray.Length - 1] = temp;

                temp = newArray[0];
                for (int j = 1; j < array.Length; j++)
                {
                    newArray[j - 1] = newArray[j];
                }

                newArray[newArray.Length - 1] = temp;
                return newArray;
            }
        }

        public int[,] KeyMerge(int[,] Ci, int[,] Di)
        {
            int[,] roundKeys = new int[16, 56];
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 28; j++)
                {
                    roundKeys[i,j]=Ci[i, j];
                }
                for (int j = 0; j < 28; j++)
                {
                    roundKeys[i, j+28] = Di[i, j];
                }
            }

            return roundKeys;
        }

        public int[,] RoundKey(int[,] keyMerges)
        {
            int[] array=new int[56];
            int[,] returnArray = new int[16,48];
            int[] permutedArray;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 56; j++)
                {
                    array[j] = keyMerges[i, j];
                }

                permutedArray=Permutation(array, Const.PC2);
                for (int j = 0; j < permutedArray.Length; j++)
                {
                    returnArray[i,j] = permutedArray[j];
                }
            }

            return returnArray;
        }

        public int[] FunctionF(int[] R, int[] roundKey)
        {
            int[] permuted = Permutation(R, Const.E);
            int[] xor = XOR(permuted, roundKey);

            int[] sBoxSubs=SBoxSubstitution(xor);
            int[] permutedSBox = Permutation(sBoxSubs, Const.P);
            return permutedSBox;
        }

        public int[] SBoxSubstitution(int[] xor)
        {
            int satir, sutun, number;
            int[] numberOfBits=new int[32];
            for (int i = 0; i < 8; i++)
            {
                satir = xor[i * 6] * 2 + xor[i * 6 + 5];
                sutun = xor[i * 6 + 1] * 8 + xor[i * 6 + 2] * 4 + xor[i * 6 + 3] * 2 + xor[i * 6 + 4];
                number=Const.SBoxes[i,satir*16+sutun];
                numberOfBits[i * 4 + 3] = number % 2;
                numberOfBits[i * 4 + 2] = (number / 2) % 2;
                numberOfBits[i * 4 + 1] = ((number / 2) / 2) % 2;
                numberOfBits[i * 4] = (((number / 2) / 2) / 2) % 2;
            }

            return numberOfBits;
        }

        public int[] XOR(int[] array1, int[] array2)
        {
            int[] xor = new int[array1.Length];
            for (int i = 0; i < xor.Length; i++)
            {
                xor[i] = (array1[i] + array2[i]) % 2;
            }

            return xor;
        }

        public int[] KeyRightRotate(int[] array, int i)
        {
            int rightCount = Const.LeftShiftsINV[i ];
            if (rightCount == 1)
            {
                int[] newArray = array;

                int temp = newArray[newArray.Length-1];
                for (int j = array.Length-1; j > 0; j--)
                {
                    newArray[j] = newArray[j - 1];
                }

                newArray[0] = temp;

                return newArray;
            }
            else if(rightCount==2)
            {
                int[] newArray = array;

                int temp = newArray[newArray.Length - 1];
                for (int j = array.Length - 1; j > 0; j--)
                {
                    newArray[j] = newArray[j - 1];
                }

                newArray[0] = temp;

                newArray = array;

                temp = newArray[newArray.Length - 1];
                for (int j = array.Length - 1; j > 0; j--)
                {
                    newArray[j] = newArray[j - 1];
                }

                newArray[0] = temp;

                return newArray;
            }
            else
            {
                return array;
            }
        }
    }
}
