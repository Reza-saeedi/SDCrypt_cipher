package com.cryptography.sdcrypt_cipher.modes.algorithms;

import com.cryptography.sdcrypt_cipher.crypto.SDCrypt;
import com.cryptography.sdcrypt_cipher.modes.OperationMode;


/**
 * ECB mode of operation.
 * The message is divided into blocks, and each block is encrypted separately.
 */
public class ECB extends OperationMode {

    public ECB(boolean encrypt, String key) {
        super(new SDCrypt(key, encrypt), encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(data, pos); // Encrypt / decrypt block
    }
}
