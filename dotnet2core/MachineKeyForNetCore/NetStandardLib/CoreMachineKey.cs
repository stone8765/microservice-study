using AspNetTicketBridge;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetStandardLib
{
    public class CoreMachineKey
    {
        public static byte[] Protect(byte[] data, params string[] purposes)
        {
            string validationKey = "CA95473474DAA16A2E4B356439BB5AB4E8A375BDCB21BEC893DBF074F5E2B66332E2798F60FEF7823F5373CE717C524A6839A77663303DDE02E28366100E2F90";
            string decryptionKey = "E851046E3A48F16CA03F56478B69E83411ECD1A67035B51F7798AC0FCF9ED153";
            string validation = "SHA1";
            string decryption = "AES";
            string primaryPurpose = "User.MachineKey.Protect";
            //public static readonly Purpose User_MachineKey_Protect = new Purpose("User.MachineKey.Protect"); // used by the MachineKey static class Protect / Unprotect methods
            return MachineKeyTicketProtector.Protect(data, decryptionKey, validationKey, decryption, validation, primaryPurpose, purposes);
        }

        public static byte[] UnProtect(byte[] data, params string[] purposes)
        {
            string validationKey = "CA95473474DAA16A2E4B356439BB5AB4E8A375BDCB21BEC893DBF074F5E2B66332E2798F60FEF7823F5373CE717C524A6839A77663303DDE02E28366100E2F90";
            string decryptionKey = "E851046E3A48F16CA03F56478B69E83411ECD1A67035B51F7798AC0FCF9ED153";
            string validation = "SHA1";
            string decryption = "AES";
            string primaryPurpose = "User.MachineKey.Protect";
            //public static readonly Purpose User_MachineKey_Protect = new Purpose("User.MachineKey.Protect"); // used by the MachineKey static class Protect / Unprotect methods
            //return MachineKeyTicketUnprotector.Unprotect(data, decryptionKey, validationKey, decryption, validation, primaryPurpose, purposes);
            return MachineKeyTicketUnprotector.Unprotect(data, decryptionKey, validationKey, decryption, validation, primaryPurpose, purposes);
        }
    }

    static class MachineKey
    {
        public static byte[] Unprotect(byte[] protectedData, string validationKey, string decryptionKey, string decryptionAlgorithmName, string validationAlgorithmName, string primaryPurpose, params string[] specificPurposes)
        {
            using (SymmetricAlgorithm symmetricAlgorithm = CryptoConfig.CreateFromName(decryptionAlgorithmName) as SymmetricAlgorithm)
            {
                symmetricAlgorithm.Key = SP800_108.DeriveKey(HexToBinary(decryptionKey), primaryPurpose, specificPurposes);
                using (KeyedHashAlgorithm keyedHashAlgorithm = CryptoConfig.CreateFromName(validationAlgorithmName) as KeyedHashAlgorithm)
                {
                    keyedHashAlgorithm.Key = SP800_108.DeriveKey(HexToBinary(validationKey), primaryPurpose, specificPurposes);
                    int blockCount = symmetricAlgorithm.BlockSize / 8;
                    int hashCount = keyedHashAlgorithm.HashSize / 8;
                    checked
                    {
                        int dataCount = protectedData.Length - blockCount - hashCount;
                        if (dataCount <= 0)
                        {
                            return null;
                        }
                        byte[] hash = keyedHashAlgorithm.ComputeHash(protectedData, 0, blockCount + dataCount);
                        if (BuffersAreEqual(protectedData, blockCount + dataCount, hashCount, hash, 0, hash.Length))
                        {
                            byte[] iv = new byte[blockCount];
                            Buffer.BlockCopy(protectedData, 0, iv, 0, iv.Length);
                            symmetricAlgorithm.IV = iv;
                            using (MemoryStream memoryStream = new MemoryStream())
                            {
                                using (ICryptoTransform transform = symmetricAlgorithm.CreateDecryptor())
                                {
                                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                                    {
                                        cryptoStream.Write(protectedData, blockCount, dataCount);
                                        cryptoStream.FlushFinalBlock();
                                        return memoryStream.ToArray();
                                    }
                                }
                            }
                        }
                        return null;
                    }
                }
            }
        }

        static byte[] HexToBinary(string data)
        {
            if (data == null || data.Length % 2 != 0)
            {
                return null;
            }
            byte[] array = new byte[data.Length / 2];
            for (int i = 0; i < array.Length; i++)
            {
                int i1 = HexToInt(data[2 * i]);
                int i2 = HexToInt(data[2 * i + 1]);
                if (i1 == -1 || i2 == -1)
                {
                    return null;
                }
                array[i] = (byte)((i1 << 4) | i2);
            }
            return array;
            int HexToInt(char h)
            {
                if (h < '0' || h > '9')
                {
                    if (h < 'a' || h > 'f')
                    {
                        if (h < 'A' || h > 'F')
                        {
                            return -1;
                        }
                        return h - 65 + 10;
                    }
                    return h - 97 + 10;
                }
                return h - 48;
            }
        }

        static bool BuffersAreEqual(byte[] buffer1, int buffer1Offset, int buffer1Count, byte[] buffer2, int buffer2Offset, int buffer2Count)
        {
            bool flag = buffer1Count == buffer2Count;
            for (int i = 0; i < buffer1Count; i++)
            {
                flag &= (buffer1[buffer1Offset + i] == buffer2[buffer2Offset + i % buffer2Count]);
            }
            return flag;
        }

        static class SP800_108
        {
            public static byte[] DeriveKey(byte[] keyDerivationKey, string primaryPurpose, params string[] specificPurposes)
            {
                using (HMACSHA512 hmac = new HMACSHA512(keyDerivationKey))
                {
                    GetKeyDerivationParameters(out byte[] label, out byte[] context, primaryPurpose, specificPurposes);
                    return DeriveKeyImpl(hmac, label, context, keyDerivationKey.Length * 8);
                }
            }

            private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
            {
                int labelLength = (label != null) ? label.Length : 0;
                int contextLength = (context != null) ? context.Length : 0;
                checked
                {
                    byte[] array = new byte[4 + labelLength + 1 + contextLength + 4];
                    if (labelLength != 0)
                    {
                        Buffer.BlockCopy(label, 0, array, 4, labelLength);
                    }
                    if (contextLength != 0)
                    {
                        Buffer.BlockCopy(context, 0, array, 5 + labelLength, contextLength);
                    }
                    WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, array, 5 + labelLength + contextLength);
                    int i = 0;
                    int blocks = unchecked(keyLengthInBits / 8);
                    byte[] result = new byte[blocks];
                    uint pos = 1u;
                    while (blocks > 0)
                    {
                        WriteUInt32ToByteArrayBigEndian(pos, array, 0);
                        byte[] hash = hmac.ComputeHash(array);
                        int minLen = Math.Min(blocks, hash.Length);
                        Buffer.BlockCopy(hash, 0, result, i, minLen);
                        i += minLen;
                        blocks -= minLen;
                        pos++;
                    }
                    return result;
                }
            }

            private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
            {
                buffer[offset] = (byte)(value >> 24);
                buffer[offset + 1] = (byte)(value >> 16);
                buffer[offset + 2] = (byte)(value >> 8);
                buffer[offset + 3] = (byte)value;
            }
        }

        static readonly UTF8Encoding SecureUTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        static void GetKeyDerivationParameters(out byte[] label, out byte[] context, string primaryPurpose, params string[] specificPurposes)
        {
            label = SecureUTF8Encoding.GetBytes(primaryPurpose);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream, SecureUTF8Encoding))
                {
                    foreach (string value in specificPurposes)
                    {
                        binaryWriter.Write(value);
                    }
                    context = memoryStream.ToArray();
                }
            }
        }
    }
}
