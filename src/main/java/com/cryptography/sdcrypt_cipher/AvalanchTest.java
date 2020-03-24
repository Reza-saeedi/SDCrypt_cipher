package com.cryptography.sdcrypt_cipher;

import com.cryptography.sdcrypt_cipher.crypto.SDCrypt;

import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

public class AvalanchTest {

    int n = 96;

    static int[][] resualt = new int[96][96];

    static String key = "";


    private static void startEncryptionTest() {

        byte[] plaintext = new byte[12];
        //new Random().nextBytes(plaintext);
      //  plaintext[11]=0x01;

        plaintext[0]=122;
        plaintext[1]=-101;
        plaintext[2]=127;
        plaintext[3]=-124;
        plaintext[4]=-92;
        plaintext[5]=81;
        plaintext[6]=-54;
        plaintext[7]=2;
        plaintext[8]=-18;
        plaintext[9]=-19;
        plaintext[10]=-115;
        plaintext[11]=37;


        System.out.println(Arrays.toString(plaintext));

        SDCrypt SDCryptEn = new SDCrypt(key, false);
        SDCryptEn.crypt(plaintext);
        System.out.println(Arrays.toString(plaintext));


        SDCrypt SDCryptDe = new SDCrypt(key, false);
        SDCryptDe.crypt(plaintext);
        System.out.println(Arrays.toString(plaintext));

        String str = null;
        try {
            str = new String(plaintext, "UTF-8");
            System.out.println(str);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        int x = 0;

    }

    private static void startOFBest() {

        byte[] plaintext = new byte[12];
        new Random().nextBytes(plaintext);


        System.out.println(Arrays.toString(plaintext));
        String randomResualt = "";
        int count = 0;
        for (int i = 0; i < 10000; i++) {
            SDCrypt SDCryptEn = new SDCrypt(key, true);
            SDCryptEn.crypt(plaintext);
            // System.out.println(Arrays.toString(plaintext));
            String cipherBlock = String.format("%8s", Integer.toBinaryString(plaintext[0] & 0xFF)).replace(' ', '0');

            if (cipherBlock.charAt(0) == '1')
                count++;
            randomResualt += cipherBlock;
            /*if (randomResualt.length() % 17 == 0)
                randomResualt += "\n";*/
        }



        writeToFile(randomResualt);


        System.out.println("count = " + count + " ->" + randomResualt);


        int x = 0;

    }

    public static void writeToFile(String args) {
        try {
            FileWriter fw = new FileWriter("E:\\ofb.txt");
            fw.write("test\n"+args);
            fw.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        System.out.println("Success...");
    }


    private static void startAvalancheTest() {
        System.out.println("startAvalancheTest ... ");
        for (int i = 0; i < 1000; i++) {
            byte[] plaintext = new byte[12];
            new Random().nextBytes(plaintext);
            avalancheRound(plaintext);
        }

        printResualt();
    }

    private static void avalancheRound(byte[] plaintext) {


        byte[] cipherText = Arrays.copyOf(plaintext, 12);
        // System.out.println("plain text: "+Arrays.toString(plaintext));
        SDCrypt SDCryptEn = new SDCrypt(key, true);
        SDCryptEn.crypt(cipherText);
        // System.out.println("cipher text: "+Arrays.toString(cipherText));


        for (int i = 11; i > -1; i--) {


            for (int pow = 0; pow < 8; pow++) {
                byte[] changePlain = Arrays.copyOf(plaintext, 12);
                int changebit = (int) Math.pow(2, pow);
                changePlain[i] = (byte) (changePlain[i] ^ changebit);
                //  System.out.println("changePlain: "+Arrays.toString(changePlain));
                SDCrypt SDCrypt = new SDCrypt(key, true);
                SDCrypt.crypt(changePlain);
                // System.out.println("changeCipher: "+Arrays.toString(changePlain));
                checkDiff(cipherText, changePlain, (11 - i) * 8 + pow);
            }

        }


    }

    private static void checkDiff(byte[] cipher, byte[] newCipher, int bitIndex) {
        for (int i = 11; i > -1; i--) {
            String cipherBlock = String.format("%8s", Integer.toBinaryString(cipher[i] & 0xFF)).replace(' ', '0');
            String newCipherBlock = String.format("%8s", Integer.toBinaryString(newCipher[i] & 0xFF)).replace(' ', '0');

            for (int index = 0; index < cipherBlock.length(); index++) {
                if (cipherBlock.charAt(index) != newCipherBlock.charAt(index)) {
                    //      System.out.println((11-i)*8+index +","+bitIndex+" : 1");
                    resualt[(11 - i) * 8 + index][bitIndex]++;
                } else {
                    ///       System.out.println((11-i)*8+index +","+bitIndex+" : 0");
                }

            }
        }
    }

    private static void printResualt() {
        int max = 0;
        int min = 1000000000;
        String maxIndex = "";
        String minIndex = "";
        for (int i = 0; i < 10; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < 10; j++) {
                if (min > resualt[i][j]) {
                    min = resualt[i][j];
                    minIndex = "(" + i + "," + j + ")";
                }
                if (max < resualt[i][j]) {
                    max = resualt[i][j];
                    maxIndex = "(" + i + "," + j + ")";
                }
                row.append(resualt[i][j]).append(" , ");

            }
            System.out.println(row);
        }

        System.out.println("min in " + minIndex + " = " + min);
        System.out.println("max in " + maxIndex + " = " + max);
    }

    public static void main(String[] args) {
        //startEncryptionTest();
        startAvalancheTest();
        //startOFBest();
    }
}
