/**
 * @author David Svaty (xsvaty01)
 * @file popHeader.h
 * @date 15.11.2021
 */

#ifndef POP3_H
#define POP3_H
#include <stdlib.h>
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

            bool delMsgMode = false;
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

            int messagesDownloaded;
            //-------------------//

            //int sock;

            //--- Methods ---//
            /**
             * @brief Object constructor
             * @param addr server adress 
             */
            Pop3Client(const char *addr);

            /**
             * @brief SSL library initializator 
             * Some functions in this method are taken from https://developer.ibm.com/tutorials/l-openssl/
             */
            void SSLinit();

            /**
             * @brief Sets certificate path 
             * @param ctx 
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
             * @brief Returns true if message is less than one day old 
             * 
             */
            bool messageIsNew(std::string msg);

            /**
             * @brief Indicates the ending of a message
             * 
             * @param msg Message to be checked  
             */
            bool messageIsEnd(std::string msg);

            /**
             * @brief UNUSED FUNCTION 
             * 
             * @param msg message to be formatted
             * @return std::string Returns formatted message  
             */
            std::string formatMessage(std::string msg); 

            /**
             * @brief Saves message
             * 
             * @param msg Message to be saved 
             */
            void saveMessage(std::string msg);

            /**
             * @brief Deletes message
             * 
             * @param messageIndex Index of message to be deleted
             */
            void deleteMessage(int messageIndex);

            /**
             * @brief Connects to server
             * Some functions in this method taken from https://developer.ibm.com/tutorials/l-openssl/
             */
            void pop3connect();
            //-----------------//

            /**
             * @brief Sends message to server
             * 
             * @param cmd Command for the server 
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
             * @brief Loops through messages and calls saveMessage function 
             */
            void pop3download(int messageIndex);

            /**
             * @brief Sends QUIT command and disconnects form server
             */
            void pop3disconnect();


        private:
            std::string username;
            std::string password;

    };
}

#endif