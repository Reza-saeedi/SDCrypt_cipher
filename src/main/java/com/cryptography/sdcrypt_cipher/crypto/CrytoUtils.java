package com.cryptography.sdcrypt_cipher.crypto;

public class CrytoUtils {
    /**
     * Turn a string into a key of the given length.
     */
    public static byte[] makeKey(String charKey, int size) {
        byte[] key = new byte[size];
        int i, j;
        for (j = 0; j < key.length; ++j) {
            key[j] = 0;
        }
        for (i = 0, j = 0; i < charKey.length(); i++, j = (j + 1) % key.length) {
            key[j] ^= (byte) charKey.charAt(i);
        }
        return key;
    }

    /**
     * XOR two blocks.
     * @param a block 1
     * @param pos offset in block 1
     * @param b block 2
     * @param blockSize size of the block to xor
     */
    public static void xor(byte[] a, int pos, byte[] b, int blockSize) {
        for (int p = 0; p < blockSize; p++) {
            a[pos + p] ^= b[p];
        }
    }

    /**
     * Concatenate two bytes into one 16-bit block.
     */
    static int concat2Bytes(int b1, int b2) {
        b1 = (b1 & 0xFF) << 8;  // xxxxxxxx00000000
        b2 = b2 & 0xFF;         // 00000000xxxxxxxx
        return (b1 | b2);       // xxxxxxxxxxxxxxxx
    }

    /**
     * Concatenate three bytes into one 16-bit block.
     */
    static int concat3Bytes(int b1, int b2, int b3) {
        b1 = (b1 & 0xFFF) << 16;  // xxxxxxxx0000000000000000
        b2 =( b2 & 0xFFF)<<8;     // 00000000xxxxxxxx00000000
        b3 =( b3 & 0xFFF);        // 0000000000000000xxxxxxxx
        return (b1 | b2|b3);       // xxxxxxxxxxxxxxxxxxxxxxxx
    }


    /**
     * Concatenate two bytes into one 16-bit block.
     */
    static int getLeft2Bytes(int b1) {
        b1 = (b1 ) >> 16;  // xxxxxxxx00000000
        return (b1 );       // xxxxxxxxxxxxxxxx
    }

    /**
     * Concatenate two bytes into one 16-bit block.
     */
    static int getRight2Bytes(int b1) {
        b1 = (b1 & 0x00FF);  // xxxxxxxx00000000
        return (b1 );       // xxxxxxxxxxxxxxxx
    }

    static int getFirstBytes(int b1) {
        b1 = (b1& 0xF00 )>> 16;  // xxxxxxxx
        return (b1 );
    }

    static int getSecondBytes(int b1) {
        b1 = (b1 & 0x0F0)>>8;  // 00000000xxxxxxxx
        return (b1 );
    }

    static int getThirdBytes(int b1) {
        b1 = (b1 & 0x00F);  // 0000000000000000xxxxxxxx
        return (b1 );
    }


    /**
     * Concatenate two bytes arrays into one.
     */
    public static byte[] concat2Bytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length + b2.length];
        int i = 0;
        for (byte aB1 : b1) {
            out[i++] = aB1;
        }
        for (byte aB2 : b2) {
            out[i++] = aB2;
        }
        return out;
    }
}
