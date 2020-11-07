#define PORT 3000
#define READ_BUFFER_SIZE 1024
#define KEY_FILE "resources/key.pem"
#define IV_FILE "resources/iv.pem"

#include <fstream>

#include "Server/Server.h"

using namespace std;

int main()
{
    unsigned char serverKey[KEY_SIZE];
    unsigned char serverIV[IV_SIZE];

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

    Server server = Server(PORT, READ_BUFFER_SIZE, serverKey, serverIV);
    server.Start();

    return 0;
}