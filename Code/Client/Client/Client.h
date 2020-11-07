#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "../../Misc/Encryption.h"

using namespace std;

class Client
{
    private: char * ip;
    private: int port;
    private: bool useECBEncryption;
    private: int serverSock;
    private: unsigned char serverKey[KEY_SIZE];
    private: unsigned char serverIV[IV_SIZE];
    private: bool clientConnected;
    private: int readBufferSize;

    public: Client(char * ip, int port, bool useECBEncryption, int readBufferSize, unsigned char serverKey[KEY_SIZE], unsigned char serverIV[IV_SIZE]);
    public: ~Client();

    public: bool Connect();
    public: bool Disconnect();

    private: void AwaitServerMessagesThreadFunc();
    private: void MessageReceivedEvent(char * message, size_t messageLen);
    private: void AwaitConsoleInput();
};