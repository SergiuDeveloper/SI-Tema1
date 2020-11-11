#define IP "127.0.0.1"
#define PORT 3000
#define READ_BUFFER_SIZE 1024
#define KEY_FILE "../resources/key.pem"
#define IV_FILE "../resources/iv.pem"

#include <fstream>
#include <string.h>

#include "Client/Client.h"

int main(int argc, char ** argv)
{
    unsigned char serverKey[KEY_SIZE];
    unsigned char serverIV[IV_SIZE];

    bool useECBEncryption = (argc > 1 && (strcmp(argv[1], "ecb") == 0 || strcmp(argv[1], "ECB") == 0));

    int i;
    char c;

    ifstream keyFile(KEY_FILE);
    i = 0;
    while (i < KEY_SIZE && !keyFile.eof())
    {
        keyFile.get(c);
        serverKey[i] = c;
        ++i;
    }
    keyFile.close();
    
    ifstream ivFile(IV_FILE);
    i = 0;
    while (i < IV_SIZE && !ivFile.eof())
    {
        ivFile.get(c);
        serverIV[i] = c;
        ++i;
    }
    ivFile.close();

    Client client = Client((char *)IP, PORT, useECBEncryption, READ_BUFFER_SIZE, serverKey, serverIV);
    client.Connect();

    return 0;
}