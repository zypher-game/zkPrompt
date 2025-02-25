pragma circom 2.1.6;

include "aes/cipher.circom";
include "../utils/utils.circom";
include "gctr.circom";


/// AESCTR with 128 bit key authenticated encryption.
///
/// Parameters:
/// l: length of the plaintext
///
/// Inputs:
/// key: 128-bit key
/// iv: initialization vector (96 bit)
/// plainText: plaintext to be encrypted
///
/// Outputs:
/// cipherText: encrypted ciphertext
///
template AESCTR(l) {
    // Inputs
    signal input key[16];
    signal input iv[12];
    signal input plainText[l];
    // Outputs
    signal output cipherText[l];

    signal J0[4][4];
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 4; j++) {
           J0[j][i] <== iv[i*4+j];
        }
    }
    var counter[4] = [0,0,0,2];
    for (var i = 0; i < 4; i++) {
        J0[i][3] <== counter[i];
    }

    component gctr = GCTR(l);
    gctr.key <== key;
    gctr.initialCounterBlock <== J0;
    gctr.plainText <== plainText;

    cipherText <== gctr.cipherText;
}