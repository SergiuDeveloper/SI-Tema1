#include "Client.h"

Client::Client(char * ip, int port, bool useECBEncryption, int readBufferSize, unsigned char serverKey[KEY_SIZE], unsigned char serverIV[IV_SIZE]) :
    ip(ip), port(port), useECBEncryption(useECBEncryption), readBufferSize(readBufferSize)
{
    for (int i = 0; i < KEY_SIZE; ++i)
        this->serverKey[i] = serverKey[i];
    for (int i = 0; i < IV_SIZE; ++i)
        this->serverIV[i] = serverIV[i];
    clientConnected = false;
}

Client::~Client()
{
    Disconnect();
}

bool Client::Connect()
{
    if (clientConnected)
        return false;

    if ((serverSock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return false;

    sockaddr_in serverSockAddr;
    serverSockAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &serverSockAddr.sin_addr);
    serverSockAddr.sin_port = htons(port);

    if (connect(serverSock, (sockaddr *)&serverSockAddr, sizeof(serverSockAddr)) < 0)
    {
        cout<<"Failed to connect to "<<ip<<':'<<port<<"!\n";
        return false;
    }

    clientConnected = true;

    cout<<"Connected to "<<ip<<':'<<port<<"!\n";

    char initialMessage[3];
    strcpy(initialMessage, useECBEncryption ? "ECB" : "CFB");
    size_t initialMessageEncryptedLen;
    unsigned char * initialMessageEncrypted = Encryption::CFB::Encrypt((unsigned char *)initialMessage, strlen(initialMessage), serverKey, KEY_SIZE, serverIV, IV_SIZE, initialMessageEncryptedLen);
    write(serverSock, initialMessageEncrypted, initialMessageEncryptedLen);
    
    unsigned char initialMessageResponseEncrypted[KEY_SIZE];
    size_t initialMessageResponseEncryptedLen;
    initialMessageResponseEncryptedLen = read(serverSock, initialMessageResponseEncrypted, KEY_SIZE);
    unsigned char * initialMessageResponse = Encryption::CFB::Decrypt(initialMessageResponseEncrypted, KEY_SIZE, serverKey, KEY_SIZE, serverIV, IV_SIZE, initialMessageResponseEncryptedLen);
    
    unsigned char initialMessageResponseEncryptedSec[IV_SIZE];
    size_t initialMessageResponseEncryptedSecLen;
    initialMessageResponseEncryptedLen = read(serverSock, initialMessageResponseEncryptedSec, IV_SIZE);
    unsigned char * initialMessageResponseSec = Encryption::CFB::Decrypt(initialMessageResponseEncryptedSec, IV_SIZE, serverKey, KEY_SIZE, serverIV, IV_SIZE, initialMessageResponseEncryptedSecLen);

    for (int i = 0; i < KEY_SIZE; ++i)
        serverKey[i] = initialMessageResponse[i];
    for (int i = 0; i < IV_SIZE; ++i)
        serverIV[i] = initialMessageResponseSec[i];

    thread awaitServerMessagesThread = thread(&Client::AwaitServerMessagesThreadFunc, this);
    awaitServerMessagesThread.detach();

    AwaitConsoleInput();

    return true;
}

bool Client::Disconnect()
{
    if (!clientConnected)
        return false;

    close(serverSock);

    clientConnected = false;

    cout<<"Disconnected!\n";

    return true;
}

void Client::AwaitServerMessagesThreadFunc()
{
    bool serverRunning = true;
    size_t readBufferLen;
    char readBuffer[readBufferSize];
    while (clientConnected && serverRunning)
        switch (readBufferLen = read(serverSock, readBuffer, readBufferSize))
        {
            case -1:
                break;
            case 0:
                serverRunning = false;
                break;
            default:
                MessageReceivedEvent(readBuffer, readBufferLen);         
        }

    Disconnect();
}

void Client::MessageReceivedEvent(char * message, size_t messageLen)
{
    size_t decrpytedMessageLen;

    unsigned char * decryptedMessage = useECBEncryption ?
        Encryption::ECB::Decrypt((unsigned char *)message, messageLen, serverKey, KEY_SIZE, decrpytedMessageLen) :
        Encryption::CFB::Decrypt((unsigned char *)message, messageLen, serverKey, KEY_SIZE, serverIV, IV_SIZE, decrpytedMessageLen)
    ;

    cout<<decryptedMessage;
}

void Client::AwaitConsoleInput()
{
    size_t readBufferLen;
    char * inputBuffer = new char[readBufferSize];
    size_t encryptedMessageLen;
    unsigned char * encryptedMessage;
    while (clientConnected)
    {
        readBufferLen = readBufferSize;
        readBufferLen = ::getline(&inputBuffer, &readBufferLen, stdin);

        encryptedMessage = useECBEncryption ?
            Encryption::ECB::Encrypt((unsigned char *)inputBuffer, readBufferLen, serverKey, KEY_SIZE, encryptedMessageLen) :
            Encryption::CFB::Encrypt((unsigned char *)inputBuffer, readBufferLen, serverKey, KEY_SIZE, serverIV, IV_SIZE, encryptedMessageLen)
        ;

        write(serverSock, encryptedMessage, encryptedMessageLen);
    }
}