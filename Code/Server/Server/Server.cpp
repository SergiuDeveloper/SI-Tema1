#include "Server.h"

Server::Server(int port, int readBufferSize, unsigned char serverKey[KEY_SIZE], unsigned char serverIV[IV_SIZE]) : port(port), readBufferSize(readBufferSize)
{
    for (int i = 0; i < KEY_SIZE; ++i)
        this->serverKey[i] = serverKey[i];
    for (int i = 0; i < IV_SIZE; ++i)
        this->serverIV[i] = serverIV[i];
    isRunning = false;
}

Server::~Server()
{
    Stop();
}

bool Server::Start()
{
    if (isRunning)
        return false;

    if ((serverSock = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        return false;

    sockaddr_in serverSockAddr;
    serverSockAddr.sin_family = AF_INET;
    serverSockAddr.sin_addr.s_addr = INADDR_ANY;
    serverSockAddr.sin_port = htons(port);
    if (bind(serverSock, (sockaddr *)&serverSockAddr, sizeof(serverSockAddr)) < 0)
        return false;

    if (listen(serverSock, SOMAXCONN) < 0)
        return false;

    isRunning = true;

    cout<<"Server started on port "<<port<<"!\n";

    int clientSock;
    int clientID;
    sockaddr_in clientSockAddr;
    socklen_t clientSockAddrLen;
    thread awaitClientMessagesThread;
    stringstream clientConnectedMessageStream;
    string clientConnectedMessage;
    while (isRunning)
    {
        clientSock = accept(serverSock, (sockaddr *)&clientSockAddr, (socklen_t *)&clientSockAddrLen);

        clientSocks.push_back(clientSock);
        clientChoseEncryptionMethod.push_back(false);
        clientUsesECB.push_back(false);
        clientActive.push_back(true);
        keys.push_back(nullptr);
        ivs.push_back(nullptr);

        clientID = clientSocks.size() - 1;

        clientConnectedMessageStream.str("");
        clientConnectedMessageStream<<"Client "<<clientID<<" connected!\n";
        clientConnectedMessage = clientConnectedMessageStream.str();

        cout<<clientConnectedMessage;

        awaitClientMessagesThread = thread(&Server::AwaitClientMessagesThreadFunc, this, clientID);
        awaitClientMessagesThread.detach();

        unsigned char * encryptedMessage;
        size_t encryptedMessageLen;
        for (int i = 0; i < clientSocks.size(); ++i)
            if (i != clientID && clientChoseEncryptionMethod[i] && clientActive[i])
            {
                encryptedMessage = clientUsesECB[i] ?
                    Encryption::ECB::Encrypt((unsigned char *)clientConnectedMessage.c_str(), clientConnectedMessage.size(), keys[i], KEY_SIZE, encryptedMessageLen) :
                    Encryption::CFB::Encrypt((unsigned char *)clientConnectedMessage.c_str(), clientConnectedMessage.size(), keys[i], KEY_SIZE, ivs[i], IV_SIZE, encryptedMessageLen)
                ;

                write(clientSocks[i], encryptedMessage, encryptedMessageLen);
            }
    }

    return true;
}

bool Server::Stop()
{
    if (!isRunning)
        return false;

    for (auto & clientSock: clientSocks)
        close(clientSock);
    close(serverSock);

    isRunning = false;

    cout<<"Server stopped!\n";

    return true;
}

void Server::AwaitClientMessagesThreadFunc(int clientID)
{
    int clientSock = clientSocks[clientID];

    bool clientConnected = true;
    size_t readBufferLen;
    char readBuffer[readBufferSize];
    
    while (isRunning && clientConnected)
        switch (readBufferLen = read(clientSock, readBuffer, readBufferSize))
        {
            case -1:
                break;
            case 0:
                clientConnected = false;
                break;
            default:
                MessageReceivedEvent(clientID, readBuffer, readBufferLen);
                break;    
        }

    ClientDisconnectedEvent(clientID);
}

void Server::MessageReceivedEvent(int clientID, char * message, size_t messageLen)
{
    unsigned char * decryptedMessage;
    size_t decryptedMessageLen;

    if (!clientChoseEncryptionMethod[clientID])
    {
        clientChoseEncryptionMethod[clientID] = true;

        decryptedMessage = Encryption::CFB::Decrypt((unsigned char *)message, messageLen, serverKey, KEY_SIZE, serverIV, IV_SIZE, decryptedMessageLen);

        clientUsesECB[clientID] = (decryptedMessageLen >= 3 && (strcmp((char *)decryptedMessage, "ecb") == 0 || strcmp((char *)decryptedMessage, "ECB") == 0));

        keys[clientID] = new unsigned char[KEY_SIZE];
        RAND_bytes(keys[clientID], KEY_SIZE);
        ivs[clientID] = new unsigned char[IV_SIZE];
        RAND_bytes(ivs[clientID], IV_SIZE);

        size_t encryptedKeyLen;
        unsigned char * encryptedKey = Encryption::CFB::Encrypt(keys[clientID], KEY_SIZE, serverKey, KEY_SIZE, serverIV, IV_SIZE, encryptedKeyLen);
        size_t encryptedIVLen;
        unsigned char * encryptedIV = Encryption::CFB::Encrypt(ivs[clientID], IV_SIZE, serverKey, KEY_SIZE, serverIV, IV_SIZE, encryptedIVLen);

        write(clientSocks[clientID], encryptedKey, KEY_SIZE);
        write(clientSocks[clientID], encryptedIV, IV_SIZE);

        return;
    }

    decryptedMessage = clientUsesECB[clientID] ?
        Encryption::ECB::Decrypt((unsigned char *)message, messageLen, keys[clientID], KEY_SIZE, decryptedMessageLen) : 
        Encryption::CFB::Decrypt((unsigned char *)message, messageLen, keys[clientID], KEY_SIZE, ivs[clientID], IV_SIZE, decryptedMessageLen)
    ;

    int clientID_copy = clientID;
    int digits = 0;
    while (clientID_copy != 0)
    {
        clientID_copy /= 10;
        ++digits;
    }
    if (digits == 0)
        digits = 1;

    unsigned char * modifiedDecryptedMessage = new unsigned char[decryptedMessageLen + digits + 2];
    if (clientID == 0)
        modifiedDecryptedMessage[0] = '0';
    else
    {
        clientID_copy = clientID;
        int digits_copy = digits;
        while (digits_copy != 0)
        {
            modifiedDecryptedMessage[digits_copy - 1] = (clientID_copy % 10) + '0';
            --digits_copy;
            clientID_copy /= 10;
        }
    }

    modifiedDecryptedMessage[digits] = ':';
    modifiedDecryptedMessage[digits + 1] = ' ';

    for (int i = 0; i < decryptedMessageLen; ++i)
        modifiedDecryptedMessage[digits + 2 + i] = decryptedMessage[i];
    decryptedMessageLen = decryptedMessageLen + digits + 2;

    cout<<modifiedDecryptedMessage;

    unsigned char * encryptedMessage;
    size_t encryptedMessageLen;
    for (int i = 0; i < clientSocks.size(); ++i)
        if (i != clientID && clientChoseEncryptionMethod[i] && clientActive[i])
        {
            encryptedMessage = clientUsesECB[i] ?
                Encryption::ECB::Encrypt(modifiedDecryptedMessage, decryptedMessageLen, keys[i], KEY_SIZE, encryptedMessageLen) :
                Encryption::CFB::Encrypt(modifiedDecryptedMessage, decryptedMessageLen, keys[i], KEY_SIZE, ivs[i], IV_SIZE, encryptedMessageLen)
            ;

            write(clientSocks[i], encryptedMessage, encryptedMessageLen);
        }
}

void Server::ClientDisconnectedEvent(int clientID)
{
    close(clientSocks[clientID]);

    clientActive[clientID] = false;

    stringstream clientDisconnectedMessageStream;
    string clientDisconnectedMessage;

    clientDisconnectedMessageStream.str("");
    clientDisconnectedMessageStream<<"Client "<<clientID<<" disconnected!\n";
    clientDisconnectedMessage = clientDisconnectedMessageStream.str();

    cout<<clientDisconnectedMessage;

    unsigned char * encryptedMessage;
    size_t encryptedMessageLen;
    for (int i = 0; i < clientSocks.size(); ++i)
        if (i != clientID && clientChoseEncryptionMethod[i] && clientActive[i])
        {
            encryptedMessage = clientUsesECB[i] ?
                Encryption::ECB::Encrypt((unsigned char *)clientDisconnectedMessage.c_str(), clientDisconnectedMessage.size(), keys[i], KEY_SIZE, encryptedMessageLen) :
                Encryption::CFB::Encrypt((unsigned char *)clientDisconnectedMessage.c_str(), clientDisconnectedMessage.size(), keys[i], KEY_SIZE, ivs[i], IV_SIZE, encryptedMessageLen)
            ;

            write(clientSocks[i], encryptedMessage, encryptedMessageLen);
        }
}