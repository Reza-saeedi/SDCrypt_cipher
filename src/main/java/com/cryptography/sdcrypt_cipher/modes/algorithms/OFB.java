package com.cryptography.sdcrypt_cipher.modes.algorithms;

import com.cryptography.sdcrypt_cipher.crypto.CrytoUtils;
import com.cryptography.sdcrypt_cipher.crypto.SDCrypt;
import com.cryptography.sdcrypt_cipher.modes.OperationMode;

/**
 * OFB mode of operation.
 * It generates keystream blocks, which are then XORed with the plaintext blocks to get the ciphertext.
 * ISO 10116: requires an n-bit feedback -> more secure.
 */
public class OFB extends OperationMode {

    private int blockSize;
    private byte[] feedback;

    public OFB(String key) {
        super(new SDCrypt(key, true), true);
        blockSize = idea.getBlockSize();
        feedback = CrytoUtils.makeKey(key, blockSize); // Get initial vector (IV) from user key
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(feedback);                           // Encrypt feedback
        CrytoUtils.xor(data, pos, feedback, blockSize); // XOR data and feecback
    }
}