#include <iostream>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "popHeader.h"

using namespace pop3cl;

Pop3Client::Pop3Client(std::string addr){
        serverAddr = addr;
        serverPort = 110;
        encryptedComm = false;
        encryptedSTLS = false;
        certificate.certificateGiven = false;
        deleteMessage = false;
        newMsgMode = false;
        authentisation.authGiven = false;
        output.outGiven = false;        

        if((socket = socket(AF_INET,SOCK_STREAM,serverPort)) < 0){
                cerr << "error: socket creation failed" << endl;
                exit(1);
        }       
        
}

Pop3Client::pop3connect(){
        struct sockaddr_in conn_param;
        conn_param.sin_family = AF_INET;
        conn_param.sin_port = htons(serverPort);
        

}

