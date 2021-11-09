/**
 * @author David Svaty (xsvaty01)
 * @file popHeader.h
 * @date 
 */

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
            std::string serverAddr;
            int serverPort;

            std::string hostname;

            bool encryptedComm;
            bool encryptedSTLS;

            struct certificateStruct {
                bool certificateGiven;
                bool certificatePathGiven;
                char *certificateFile;
                char* certificatePath;
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

            SSL_CTX *ctx;
            SSL *ssl;
            //-------------------//

            //int sock;

            //--- Methods ---//
            /**
             * @brief Object constructor
             * @param addr server adress 
             */
            Pop3Client(const char *addr);

            /**
             * @brief Class destructor
             * 
             */
            ~Pop3Client();

            /**
             * @brief SSL library initializator 
             */
            void SSLinit();

            /**
             * @brief Sets certificate path 
             */
            void setCertificate(SSL_CTX *ctx); 
            
            /**
             * @brief Clears buffer
             * 
             */
            void clearBuffer();

            /**
             * @brief Sets user credentials 
             * 
             * Works as a simple config file parser
             * Format:
             * username = *username*
             * password = *password*
             */
            void setUser();

            /**
             * @brief Saves message
             * 
             */
            void saveMessage();

            /**
             * @brief Connects to server
             * 
             */
            void pop3connect();
            //-----------------//

            /**
             * @brief Sends message to server
             * 
             * @param cmd 
             */
            void pop3send(std::string cmd);

            /**
             * @brief Reads message from server and saves it to buffer
             * 
             */
            void pop3read();

            /**
             * @brief Checks whether server response is "+OK"
             * 
             */
            void pop3isOk();

            /**
             * @brief Sets user and password parameters
             * 
             */
            void pop3authenticate();

            /**
             * @brief Sends stat parameter
             *  
             */
            void pop3stat();

            /**
             * 
             */
            void pop3download(int messageIndex);

            /**
             * @brief Sends QUIT command and disconnects form server
             * 
             */
            void pop3disconnect();


        private:
            std::string username;
            std::string password;

    };
}

#endif