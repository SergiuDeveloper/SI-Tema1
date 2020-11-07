#define KEY_SIZE AES_BLOCK_SIZE
#define IV_SIZE AES_BLOCK_SIZE

#include <vector>
#include <openssl/aes.h>

using namespace std;

class Encryption
{
    private: static AES_KEY aesKey;

    private: static unsigned char * AESEncrypt(unsigned char block[AES_BLOCK_SIZE], unsigned char key[KEY_SIZE]);
    private: static unsigned char * AESDecrypt(unsigned char cipherBlock[AES_BLOCK_SIZE], unsigned char key[KEY_SIZE]);
    private: static unsigned char * PadText(unsigned char * text, size_t textLen, size_t blockLen, unsigned char paddingChar, size_t & paddedTextLen);

    public:
    class ECB
    {
        public: static unsigned char * Encrypt(unsigned char * plaintext, size_t plaintextLen, unsigned char key[KEY_SIZE], size_t keyLen, size_t & cipherTextLen);
        public: static unsigned char * Decrypt(unsigned char * cipherText, size_t cipherTextLen, unsigned char key[KEY_SIZE], size_t keyLen, size_t & plaintextLen);
    };

    public:
    class CFB
    {
        public: static unsigned char * Encrypt(unsigned char * plaintext, size_t plaintextLen, unsigned char key[KEY_SIZE], size_t keyLen, unsigned char iv[IV_SIZE], size_t ivLen, size_t & cipherTextLen);
        public: static unsigned char * Decrypt(unsigned char * cipherText, size_t cipherTextLen, unsigned char key[KEY_SIZE], size_t keyLen, unsigned char iv[IV_SIZE], size_t ivLen, size_t & plaintextLen);
    };
};