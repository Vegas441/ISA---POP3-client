#ifndef POP3_H
#define POP3_H
#include <stdlib.h>
#include <string>
#include <arpa/inet.h>


namespace pop3cl
{
    /**
     * 
     * 
     */
    class Pop3Client {

        public:
            //parameters
            std::string serverAddr;
            int serverPort;
            bool encryptedComm;
            bool encryptedSTLS;
            struct certificateStruct {
                bool certificateGiven;
                FILE *certificateFile;
            }certificate;
            bool deleteMessage = false;
            bool newMsgMode = false;
            struct authentisationStruct {
                bool authGiven = false;
                FILE* authFile;
            }authentisation;
            struct outputStruct {
                bool outGiven = false;
                FILE* outFile;
            }output;

            int socket;
    
            Pop3Client(std::string addr);

            pop3connect();


    };
}

#endif