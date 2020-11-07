#include "Encryption.h"

AES_KEY Encryption::aesKey = AES_KEY();

unsigned char * Encryption::AESEncrypt(unsigned char block[AES_BLOCK_SIZE], unsigned char key[KEY_SIZE])
{
    AES_set_encrypt_key(key, KEY_SIZE * 8, &aesKey);

    unsigned char * cipherBlock = new unsigned char[AES_BLOCK_SIZE];
    AES_encrypt(block, cipherBlock, &aesKey);

    return cipherBlock;
}

unsigned char * Encryption::AESDecrypt(unsigned char cipherBlock[AES_BLOCK_SIZE], unsigned char key[KEY_SIZE])
{
    AES_set_decrypt_key(key, KEY_SIZE * 8, &aesKey);

    unsigned char * block = new unsigned char[AES_BLOCK_SIZE];
    AES_decrypt(cipherBlock, block, &aesKey);

    return block;
}

unsigned char * Encryption::PadText(unsigned char * text, size_t textLen, size_t blockLen, unsigned char paddingChar, size_t & paddedTextLen)
{
    if (textLen % blockLen == 0)
    {
        paddedTextLen = textLen;
        return text;
    }

    int bytesToAdd = blockLen - (textLen % blockLen);
            
    unsigned char * paddedText = new unsigned char[textLen + bytesToAdd];
    for (int i = 0; i < textLen; ++i)
        paddedText[i] = text[i];
    for (int i = textLen; i < textLen + bytesToAdd; ++i)
        paddedText[i] = paddingChar;

    paddedTextLen = textLen + bytesToAdd;
    return paddedText;
}

unsigned char * Encryption::ECB::Encrypt(unsigned char * plaintext, size_t plaintextLen, unsigned char key[KEY_SIZE], size_t keyLen, size_t & cipherTextLen)
{
    size_t paddedPlaintextLen;
    unsigned char * paddedPlaintext = PadText(plaintext, plaintextLen, AES_BLOCK_SIZE, '\0', paddedPlaintextLen);
    unsigned char * paddedKey = PadText(key, keyLen, KEY_SIZE, '\0', keyLen);

    vector<unsigned char> cipherText;
    vector<unsigned char> block;
    unsigned char * cipherBlock;
    for (int i = 0; i < paddedPlaintextLen; ++i)
    {
        block.push_back(paddedPlaintext[i]);

        if ((i + 1) % AES_BLOCK_SIZE == 0)
        {
            cipherBlock = AESEncrypt(&block[0], paddedKey);
            for (int j = 0; j < AES_BLOCK_SIZE; ++j)
                cipherText.push_back(cipherBlock[j]);
            block.clear();
        }
    }

    cipherTextLen = cipherText.size();
    
    unsigned char * cipherTextStr = new unsigned char[cipherTextLen];
    for (int i = 0; i < cipherTextLen; ++i)
        cipherTextStr[i] = cipherText[i];

    return cipherTextStr;
}

unsigned char * Encryption::ECB::Decrypt(unsigned char * cipherText, size_t cipherTextLen, unsigned char key[KEY_SIZE], size_t keyLen, size_t & plaintextLen)
{
    unsigned char * paddedKey = PadText(key, keyLen, KEY_SIZE, '\0', keyLen);

    vector<unsigned char> plaintext;
    vector<unsigned char> cipherBlock;
    unsigned char * block;
    for (int i = 0; i < cipherTextLen; ++i)
    {
        cipherBlock.push_back(cipherText[i]);

        if ((i + 1) % AES_BLOCK_SIZE == 0)
        {
            block = AESDecrypt(&cipherBlock[0], paddedKey);
            for (int j = 0; j < AES_BLOCK_SIZE; ++j)
                plaintext.push_back(block[j]);
            cipherBlock.clear();
        }
    }

    plaintextLen = plaintext.size();

    unsigned char * plaintextStr = new unsigned char[plaintextLen];
    for (int i = 0; i < plaintextLen; ++i)
        plaintextStr[i] = plaintext[i];

    return plaintextStr;
}

unsigned char * Encryption::CFB::Encrypt(unsigned char * plaintext, size_t plaintextLen, unsigned char key[KEY_SIZE], size_t keyLen, unsigned char iv[IV_SIZE], size_t ivLen, size_t & cipherTextLen)
{
    unsigned char iv_copy[IV_SIZE];
    for (int i = 0; i < ivLen; ++i)
        iv_copy[i] = iv[i];
    size_t ivLen_copy = ivLen;

    size_t paddedPlaintextLen;
    unsigned char * paddedPlaintext = PadText(plaintext, plaintextLen, AES_BLOCK_SIZE, '\0', paddedPlaintextLen);
    unsigned char * paddedKey = PadText(key, keyLen, KEY_SIZE, '\0', keyLen);
    unsigned char * paddedIV = PadText(iv, ivLen, IV_SIZE, '\0', ivLen);

    vector<unsigned char> cipherText;
    vector<unsigned char> block;
    vector<unsigned char> ivBlock;
    unsigned char * cipherBlock;
    for (int i = 0; i < paddedPlaintextLen; ++i)
    {
        block.push_back(paddedPlaintext[i]);
        ivBlock.push_back(paddedIV[i % AES_BLOCK_SIZE]);

        if ((i + 1) % AES_BLOCK_SIZE == 0)
        {
            cipherBlock = AESEncrypt(&ivBlock[0], paddedKey);
            for (int j = 0; j < AES_BLOCK_SIZE; ++j)
            {
                cipherBlock[j] = cipherBlock[j] ^ block[j];
                cipherText.push_back(cipherBlock[j]);
                paddedIV[j] = cipherBlock[j];
            }

            block.clear();
            ivBlock.clear();
        }
    }

    cipherTextLen = cipherText.size();
    
    unsigned char * cipherTextStr = new unsigned char[cipherTextLen];
    for (int i = 0; i < cipherTextLen; ++i)
        cipherTextStr[i] = cipherText[i];

    for (int i = 0; i < ivLen_copy; ++i)
        iv[i] = iv_copy[i];

    return cipherTextStr;
}

unsigned char * Encryption::CFB::Decrypt(unsigned char * cipherText, size_t cipherTextLen, unsigned char key[KEY_SIZE], size_t keyLen, unsigned char iv[IV_SIZE], size_t ivLen, size_t & plaintextLen)
{
    unsigned char iv_copy[IV_SIZE];
    for (int i = 0; i < ivLen; ++i)
        iv_copy[i] = iv[i];
    size_t ivLen_copy = ivLen;

    unsigned char * paddedKey = PadText(key, keyLen, KEY_SIZE, '\0', keyLen);
    unsigned char * paddedIV = PadText(iv, ivLen, IV_SIZE, '\0', ivLen);

    vector<unsigned char> plaintext;
    vector<unsigned char> cipherBlock;
    vector<unsigned char> ivBlock;
    unsigned char * block;
    for (int i = 0; i < cipherTextLen; ++i)
    {
        cipherBlock.push_back(cipherText[i]);
        ivBlock.push_back(paddedIV[i % IV_SIZE]);

        if ((i + 1) % AES_BLOCK_SIZE == 0)
        {
            block = AESEncrypt(&ivBlock[0], paddedKey);
            for (int j = 0; j < AES_BLOCK_SIZE; ++j)
            {
                block[j] = block[j] ^ cipherBlock[j];
                plaintext.push_back(block[j]);
                paddedIV[j] = cipherBlock[j];
            }

            cipherBlock.clear();
            ivBlock.clear();
        }
    }

    plaintextLen = plaintext.size();

    unsigned char * plaintextStr = new unsigned char[plaintextLen];
    for (int i = 0; i < plaintextLen; ++i)
        plaintextStr[i] = plaintext[i];

    for (int i = 0; i < ivLen_copy; ++i)
        iv[i] = iv_copy[i];

    return plaintextStr;
}