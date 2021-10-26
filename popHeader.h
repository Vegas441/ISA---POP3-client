#ifndef POP3_H
#define POP3_H
#include <stdlib.h>
#include <string>
#include <fstream>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace pop3cl
{
    /**
     * 
     * 
     */
    class Pop3Client {

        public:

            //--- Socket ---//
            BIO *bio;
            //--------------//

            //--- Buffer ---//
            char* buffer;
            //--------------//

            //--- Parameters ---//
            std::string command;
            const char *serverAddr;
            int serverPort;

            char *hostname;

            bool encryptedComm;
            bool encryptedSTLS;

            struct certificateStruct {
                bool certificateGiven;
                char *certificateFile;
            }certificate;

            bool deleteMessage = false;
            bool newMsgMode = false;

            struct authentisationStruct {
                bool authGiven = false;
                char* authFileName;
            }authentisation;

            struct outputStruct {
                bool outGiven = false;
                std::string outDir;
            }output;
            //-------------------//

            //int sock;

            //--- Methods ---//
            /**
             * Object constructor
             * @param addr server adress 
             */
            Pop3Client(const char *addr);

            /**
             * Destructor
             * 
             */
            ~Pop3Client();

            /**
             * SSL library initializator 
             */
            void SSLinit();

            /**
             * Sets certificate path 
             */
            void setCertificate(SSL_CTX *ctx); 
            
            /**
             * Sets user credentials 
             * 
             * Works as a simple config file parser
             * Format:
             * username = *username*
             * password = *password*
             */
            void setUser();

            /**
             * Connects to server
             * 
             */
            void pop3connect();
            //-----------------//

            /**
             * Sets user and password parameters
             * 
             */
            void pop3authenticate();

            /**
             * Sends stat parameter
             *  
             */
            void pop3stat();

            /**
             * 
             */
            void pop3download(int messageIndex);


        private:
            std::string username;
            std::string password;

    };
}

#endif