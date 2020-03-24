# SDCrypt cipher

Software implementation of SDCrypt Algorithm cipher with 4 ciphering modes.

SDCrypt 96-bit Algorithm:

International Data Encryption (IDEA) + AES S-Box + SPN 


![Screenshot](https://raw.githubusercontent.com/davidmigloz/IDEA-cipher/master/docs/report/images/screenshot.gif)

- Modes of operation:
    + ECB (Electronic Codebook)
    + CBC (Cipher Block Chaining)
    + CFB (Cipher Feedback) with configurable r.
    + OBF (Output Feedback) with r = blockSize.