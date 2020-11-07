#include <vector>
#include <thread>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <string.h>

#include "../../Misc/Encryption.h"

using namespace std;

class Server
{
    private: int port;
    private: unsigned char serverKey[KEY_SIZE];
    private: unsigned char serverIV[IV_SIZE];
    private: bool isRunning;
    private: int readBufferSize;
    private: int serverSock;
    private: vector<int> clientSocks;
    private: vector<bool> clientChoseEncryptionMethod;
    private: vector<bool> clientUsesECB;
    private: vector<bool> clientActive;
    private: vector<unsigned char *> keys;
    private: vector<unsigned char *> ivs;

    public: Server(int port, int readBufferSize, unsigned char serverKey[KEY_SIZE], unsigned char serverIV[IV_SIZE]);
    public: ~Server();

    public: bool Start();
    public: bool Stop();

    private: void AwaitClientMessagesThreadFunc(int clientID);
    private: void MessageReceivedEvent(int clientID, char * message, size_t messageLen);
    private: void ClientDisconnectedEvent(int clientID);
};