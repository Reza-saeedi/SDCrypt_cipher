package com.cryptography.sdcrypt_cipher.modes;

import com.cryptography.sdcrypt_cipher.crypto.SDCrypt;

/**
 * Mode of operation.
 */
public abstract class OperationMode {

    public enum Mode {
        ECB, CBC, CFB, OFB
    }

    protected SDCrypt idea;
    protected boolean encrypt;

    public OperationMode(SDCrypt idea, boolean encrypt) {
        this.idea = idea;
        this.encrypt = encrypt;
    }

    protected abstract void crypt(byte[] data, int pos);

    void crypt(byte[] data){
        crypt(data, 0);
    }

    public boolean isEncrypt() {
        return encrypt;
    }
}
