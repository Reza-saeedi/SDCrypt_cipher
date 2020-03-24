package com.cryptography.sdcrypt_cipher.crypto;

public class SDCrypt extends BlockCipher {

    private static final int KEY_SIZE = 12;
    private static final int BLOCK_SIZE = 12;
    private static final int ROUNDS = 16;
    private static final int IDEAROUNDS = 2;

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }

    private boolean encrypt;
    private int[] subKey;
    int[] tempSubKey;


    public SDCrypt(String charKey, boolean encrypt) {
        super(KEY_SIZE, BLOCK_SIZE);
        this.encrypt = encrypt;
        setKey(charKey);
    }

    @Override
    protected void setKey(byte[] key) {
        tempSubKey = generateSubkeys(key);
        if (encrypt) {
            subKey = tempSubKey;
        } else {
            subKey = invertSubkey(tempSubKey);
        }
    }

    @SuppressWarnings({"SuspiciousNameCombination", "PointlessArithmeticExpression"})
    @Override
    public void crypt(byte[] data, int offset) {
        if (!encrypt) {
            decrypt(data, offset);
            return;
        }
        // Divide the 64-bit data block into four 16-bit sub-blocks (input of 1st round)
        int x1 = data[offset + 0] & 0xff;
        int x2 = data[offset + 1] & 0xff;
        int x3 = data[offset + 2] & 0xff;
        int x4 = data[offset + 3] & 0xff;
        int x5 = data[offset + 4] & 0xff;
        int x6 = data[offset + 5] & 0xff;
        int x7 = data[offset + 6] & 0xff;
        int x8 = data[offset + 7] & 0xff;
        int x9 = data[offset + 8] & 0xff;
        int x10 = data[offset + 9] & 0xff;
        int x11 = data[offset + 10] & 0xff;
        int x12 = data[offset + 11] & 0xff;


        // Each round
        int k = 0; // Subkey index
        for (int round = 0; round < ROUNDS; round++) {
            int[] roundResult1 = doRound(x1, x2, x3, x4, k);
            k = roundResult1[4];
            int[] roundResult2 = doRound(x5, x6, x7, x8, k);
            k = roundResult2[4];
            int[] roundResult3 = doRound(x9, x10, x11, x12, k);
            k = roundResult3[4];


            x1 = roundResult2[0];
            x2 = roundResult1[0];
            x3 = roundResult3[0];
            x4 = roundResult2[3];

            x5 = roundResult1[1];
            x6 = roundResult3[1];
            x7 = roundResult2[1];
            x8 = roundResult3[3];


            x9 = roundResult3[2];
            x10 = roundResult1[2];
            x11 = roundResult2[2];
            x12 = roundResult1[3];


        }

        data[offset + 0] = (byte) (x1);
        data[offset + 1] = (byte) (x2);
        data[offset + 2] = (byte) (x3);
        data[offset + 3] = (byte) (x4);
        data[offset + 4] = (byte) (x5);
        data[offset + 5] = (byte) (x6);
        data[offset + 6] = (byte) (x7);
        data[offset + 7] = (byte) (x8);
        data[offset + 8] = (byte) (x9);
        data[offset + 9] = (byte) (x10);
        data[offset + 10] = (byte) (x11);
        data[offset + 11] = (byte) (x12);
    }

    @Override
     void decrypt(byte[] data, int offset) {
        int x1 = data[offset + 0] & 0xff;
        int x2 = data[offset + 1] & 0xff;
        int x3 = data[offset + 2] & 0xff;
        int x4 = data[offset + 3] & 0xff;
        int x5 = data[offset + 4] & 0xff;
        int x6 = data[offset + 5] & 0xff;
        int x7 = data[offset + 6] & 0xff;
        int x8 = data[offset + 7] & 0xff;
        int x9 = data[offset + 8] & 0xff;
        int x10 = data[offset + 9] & 0xff;
        int x11 = data[offset + 10] & 0xff;
        int x12 = data[offset + 11] & 0xff;

        int k = 0; // Subkey index


        // Each round

        for (int round = 0; round < ROUNDS; round++) {
            int[] roundResult1 = invDoRound(x2, x5, x10, x12, k);
            k = roundResult1[4];
            int[] roundResult2 = invDoRound(x1, x7, x11, x4, k);
            k = roundResult2[4];
            int[] roundResult3 = invDoRound(x3, x6, x9, x8, k);
            k = roundResult3[4];

            x1 = roundResult1[0];
            x2 = roundResult1[1];
            x3 = roundResult1[2];
            x4 = roundResult1[3];

            x5 = roundResult2[0];
            x6 = roundResult2[1];
            x7 = roundResult2[2];
            x8 = roundResult2[3];

            x9 = roundResult3[0];
            x10 = roundResult3[1];
            x11 = roundResult3[2];
            x12 = roundResult3[3];

        }

        data[offset + 0] = (byte) (x1);
        data[offset + 1] = (byte) (x2);
        data[offset + 2] = (byte) (x3);
        data[offset + 3] = (byte) (x4);
        data[offset + 4] = (byte) (x5);
        data[offset + 5] = (byte) (x6);
        data[offset + 6] = (byte) (x7);
        data[offset + 7] = (byte) (x8);
        data[offset + 8] = (byte) (x9);
        data[offset + 9] = (byte) (x10);
        data[offset + 10] = (byte) (x11);
        data[offset + 11] = (byte) (x12);


    }

    private int[] doRound(int x1, int x2, int x3, int x4, int k) {
        for (int round = 0; round < IDEAROUNDS; round++) {
            int y1 = mul(x1, subKey[k++]);          // Multiply X1 and the first subkey
            int y2 = add(x2, subKey[k++]);          // Add X2 and the second subkey
            int y3 = add(x3, subKey[k++]);          // Add X3 and the third subkey
            int y4 = mul(x4, subKey[k++]);          // Multiply X4 and the fourth subkey
            int y5 = y1 ^ y3;                       // XOR the results of y1 and y3
            int y6 = y2 ^ y4;                       // XOR the results of y2 and y4
            int y7 = mul(y5, subKey[k++]);          // Multiply the results of y5 with the fifth subkey
            int y8 = add(y6, y7);                   // Add the results of y6 and y7
            int y9 = mul(y8, subKey[k++]);          // Multiply the results of y8 with the sixth subkey
            int y10 = add(y7, y9);                  // Add the results of y7 and y9

            x1 = y1 ^ y9;                           // XOR the results of steps y1 and y9
            x2 = y3 ^ y9;                           // XOR the results of steps y3 and y9
            x3 = y2 ^ y10;                          // XOR the results of steps y2 and y10
            x4 = y4 ^ y10;
        }

        int r1 = mul(x1, subKey[k++]);              // Multiply X1 and the first subkey
        int r2 = add(x3, subKey[k++]);              // Add X2 and the second subkey (x2-x3 are swaped)
        int r3 = add(x2, subKey[k++]);              // Add X3 and the third subkey
        int r4 = mul(x4, subKey[k++]);


        int[] arrays = {subBytes(r1), subBytes(r2), subBytes(r3), subBytes(r4), k};


        return arrays;
    }

    private int[] invDoRound(int x1, int x2, int x3, int x4, int k) {

        x1 = invSubBytes(x1);
        x2 = invSubBytes(x2);
        x3 = invSubBytes(x3);
        x4 = invSubBytes(x4);
        for (int round = 0; round < IDEAROUNDS; round++) {
            int y1 = mul(x1, subKey[k++]);          // Multiply X1 and the first subkey
            int y2 = add(x2, subKey[k++]);          // Add X2 and the second subkey
            int y3 = add(x3, subKey[k++]);          // Add X3 and the third subkey
            int y4 = mul(x4, subKey[k++]);          // Multiply X4 and the fourth subkey
            int y5 = y1 ^ y3;                       // XOR the results of y1 and y3
            int y6 = y2 ^ y4;                       // XOR the results of y2 and y4
            int y7 = mul(y5, subKey[k++]);          // Multiply the results of y5 with the fifth subkey
            int y8 = add(y6, y7);                   // Add the results of y6 and y7
            int y9 = mul(y8, subKey[k++]);          // Multiply the results of y8 with the sixth subkey
            int y10 = add(y7, y9);                  // Add the results of y7 and y9

            x1 = y1 ^ y9;                           // XOR the results of steps y1 and y9
            x2 = y3 ^ y9;                           // XOR the results of steps y3 and y9
            x3 = y2 ^ y10;                          // XOR the results of steps y2 and y10
            x4 = y4 ^ y10;
        }

        int r1 = mul(x1, subKey[k++]);              // Multiply X1 and the first subkey
        int r2 = add(x3, subKey[k++]);              // Add X2 and the second subkey (x2-x3 are swaped)
        int r3 = add(x2, subKey[k++]);              // Add X3 and the third subkey
        int r4 = mul(x4, subKey[k++]);


        int[] arrays = {r1, r2, r3, r4, k};


        return arrays;
    }


    /**
     * Creating the subkeys from the user key.
     *
     * @param userKey 128-bit user key
     * @return 52 16-bit key sub-blocks (six for each of the eight rounds and four more for the output transformation)
     */
    private static int[] generateSubkeys(byte[] userKey) {
        if (userKey.length != 12) {
            throw new IllegalArgumentException();
        }

        int[] key = new int[ROUNDS * (3 * (IDEAROUNDS * 6 + 4))]; // 52 16-bit subkeys

        // The 128-bit userKey is divided into eight 16-bit subkeys
        int b1, b2;
        for (int i = 0; i < userKey.length / 2; i++) {
            key[i] = userKey[i];
        }

        // The key is rotated 13 bits to the left and again divided into eight subkeys.
        // The first four are used in round 2; the last four are used in round 3.
        // The key is rotated another 13 bits to the left for the next eight subkeys, and so on.
        for (int i = userKey.length / 2; i < key.length; i++) {
            // It starts combining k1 shifted 9 bits with k2. This is 8 bits of k0 + 5 bits shifted from k1 = 13 bits
            b1 = key[(i + 1) % 6 != 0 ? i - 5 : i - 11] << 5;   // k1,k2,k3...k6,k7,k0,k9, k10...k14,k15,k8,k17,k18...
            b2 = key[(i + 2) % 6 < 2 ? i - 10 : i - 4] >>> 3;   // k2,k3,k4...k7,k0,k1,k10,k11...k15,k8, k9,k18,k19...
            key[i] = (b1^b2) & 0xff;
        }
        return key;
    }

    /**
     * Reverse and invert the subkeys to get the decryption subkeys.
     * They are either the additive or multiplicative inverses of the encryption subkeys in reverse order.
     *
     * @param subkey subkeys
     * @return inverted subkey
     */
    private static int[] invertSubkey(int[] subkey) {
        int[] invSubkey = new int[subkey.length];
        int p = 0;


        for (int j = ROUNDS; j >= 1; j--) {
            for (int z = 1; z <= 3; z++) {
                // For the final output transformation (round 9)
                int i = (((j - 1) * 3) * (IDEAROUNDS * 6 + 4)) + ((z - 1) * (IDEAROUNDS * 6 + 4) + IDEAROUNDS * 6);

                invSubkey[i] = mulInv(subkey[p++]);     // 48 <- 0
                invSubkey[i + 1] = addInv(subkey[p++]);     // 49 <- 1
                invSubkey[i + 2] = addInv(subkey[p++]);     // 50 <- 2
                invSubkey[i + 3] = mulInv(subkey[p++]);     // 51 <- 3
                // From round 8 to 2
                for (int r = IDEAROUNDS - 1; r > 0; r--) {
                    i = (((j - 1) * 3) * (IDEAROUNDS * 6 + 4)) + ((z - 1) * (IDEAROUNDS * 6 + 4) + r * 6);
                    invSubkey[i + 4] = subkey[p++];         // 46 <- 4 ...
                    invSubkey[i + 5] = subkey[p++];         // 47 <- 5 ...
                    invSubkey[i] = mulInv(subkey[p++]); // 42 <- 6 ...
                    invSubkey[i + 2] = addInv(subkey[p++]); // 44 <- 7 ...
                    invSubkey[i + 1] = addInv(subkey[p++]); // 43 <- 8 ...
                    invSubkey[i + 3] = mulInv(subkey[p++]); // 45 <- 9 ...
                }
                // Round 1
                i = (((j - 1) * 3) * (IDEAROUNDS * 6 + 4)) + ((z - 1) * (IDEAROUNDS * 6 + 4));
                invSubkey[i + 4] = subkey[p++];                 // 4 <- 46
                invSubkey[i + 5] = subkey[p++];                 // 5 <- 47
                invSubkey[i + 0] = mulInv(subkey[p++]);         // 0 <- 48
                invSubkey[i + 1] = addInv(subkey[p++]);         // 1 <- 49
                invSubkey[i + 2] = addInv(subkey[p++]);         // 2 <- 50
                invSubkey[i + 3] = mulInv(subkey[p++]);           // 3 <- 51

            }

        }


        return invSubkey;
    }

    /**
     * Addition in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int add(int x, int y) {
        return (x + y) & 0xFF;
    }

    /**
     * Additive inverse in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int addInv(int x) {
        return (0x100 - x) & 0xFF;
    }

    /**
     * Multiplication in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * Range [0, 0xFFFF].
     */
    private static int mul(int x, int y) {
        long m = (long) x * y;
        if (m != 0) {
            return (int) (m % 0x101) & 0xFF;
        } else {
            if (x != 0 || y != 0) {
                return (1 - x - y) & 0xFF;
            }
            return 1;
        }
    }

    /**
     * Multiplicative inverse in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * It uses Extended Euclidean algorithm to compute the inverse.
     * For the purposes of IDEA, the all-zero sub-block is considered to represent 2^16 = −1
     * for multiplication modulo 216 + 1; thus the multiplicative inverse of 0 is 0.
     * Range [0, 0xFFFF].
     */

    static int mulInv(int a) {
        if (a <= 1) {
            // 0 and 1 are their own inverses
            return a;
        }
        int m = 0x101;
        a = a % m;
        for (int x = 1; x < m; x++)
            if ((a * x) % m == 1)
                return x;
        return 1;
    }


    private int expand24To32(int b) {
        return b;
    }

    private int expandReverse32To24(int b) {
        return b;
    }


    private int subBytes(int si) {
        int x = (si & 0xf0) >> 4;
        int y = (si & 0x0f);
        int sub = SBox.getInstance().apply(x, y);
        return sub;
    }


    private int invSubBytes(int si) {
        int x = (si & 0xf0) >> 4;
        int y = (si & 0x0f);
        int sub = SBox.getInstance().invApply(x, y);
        return sub;
    }
}
