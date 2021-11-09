/**
 * @author David Svaty (xsvaty01)
 * @file popHeader.cpp
 * @date 
 */

#include <iostream>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "popHeader.h"

#define BUFFSIZE 1024
#define ENDLINE "\r\n\0"

using namespace pop3cl;
using namespace std;

Pop3Client::Pop3Client(const char* addr){

        buffer = (char*)malloc(BUFFSIZE);
        
        serverAddr = string(addr);
        serverPort = 110;
        encryptedComm = false;
        encryptedSTLS = false;
        certificate.certificateGiven = false;
        certificate.certificatePathGiven = false;
        deleteMessage = false;
        newMsgMode = false;
        authentisation.authGiven = false;
        output.outGiven = false;        

}

Pop3Client::~Pop3Client(){
        buffer = NULL;
        free(buffer);
}

void Pop3Client::SSLinit(){
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(SSLv23_client_method());
}

void Pop3Client::setCertificate(SSL_CTX *ctx){
        if(certificate.certificateGiven) {
                try {   
                        if(!SSL_CTX_load_verify_locations(ctx,certificate.certificateFile,NULL)) throw -1;
                }
                catch(int e){
                        cerr << "error: invalid certificate" << endl;
                        exit(1);
                }
        }
        else if(certificate.certificatePathGiven){
                try {   
                        if(!SSL_CTX_load_verify_locations(ctx,NULL,certificate.certificatePath)) throw -1;
                }
                catch(int e){
                        cerr << "error: invalid certificate" << endl;
                        exit(1);
                }
        }
        else {
                SSL_CTX_set_default_verify_paths(ctx);
        }

        if(SSL_get_verify_result(ssl) != X509_V_OK) {
                cerr << "error: failed to verify certificates" << endl;
                exit(1);
        }
}

void Pop3Client::clearBuffer(){
        memset(buffer,0,1024);
}

void Pop3Client::setUser(){
        
        /**
         * Correct file structure:
         *      username = *username*
         *      password = *password* 
         */
        ifstream afile(authentisation.authFileName);
        
        string uname;
        getline(afile,uname);
        if(uname.substr(0,8).compare("username") != 0) {
                cerr << "error: incorrect authentisation file structure" << endl;
                exit(1);
        }
        username = uname.substr(uname.find('=')+2,uname.length());
        
        string pwd;
        getline(afile,pwd);
        if(pwd.substr(0,8).compare("password") != 0) {
                cerr << "error: incorrect authentisation file structure" << endl;
                exit(1);
        }
        password = pwd.substr(pwd.find('=')+2,uname.length());
}

void Pop3Client::saveMessage() {
        cout << "saving message" << endl;
        string msg(buffer);
}

void Pop3Client::pop3connect(){

        //Sets hostname
        hostname = serverAddr + ":" + to_string(serverPort);
        //SSL initialization
        SSLinit();

        if(encryptedComm || encryptedSTLS){
                bio = BIO_new_ssl_connect(ctx);
                //upgrades the socket 
                BIO* Cssl = BIO_new_ssl(ctx,1);
                BIO_push(Cssl, bio);
                //---------
                BIO_get_ssl(bio, & ssl);
                SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
                BIO_set_conn_hostname(bio,hostname.c_str());    //segfault bez encrypted komunikacie 
        }
        //cout << hostname << endl;

        
        try {
                if((bio = BIO_new_connect(hostname.c_str())) == NULL) throw -1;
        }
        catch(int e){
                cerr << "error: connection failed" << endl;
                exit(1);
        }

        if(encryptedComm || encryptedSTLS)
                setCertificate(ctx);

        try {
                if(BIO_do_connect(bio) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: connection failed" << endl;
                exit(1);
        }

        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                cerr << "error: no answer recieved" << endl;
                exit(1);
        }
        
        
        if(strstr(buffer,"+OK") != NULL){
                cout << buffer;
        }else{
                cerr << "error: server not responding" << endl;
                exit(1);
        }

        if(encryptedSTLS){

                command = "STLS"; command += ENDLINE;
                if(BIO_write(bio,command.c_str(),command.length()) <= 0){
                        cerr << "error: error ocurred while sending STLS paramete" << endl;
                        exit(1);
                }
                if(BIO_read(bio,buffer,BUFFSIZE) < 0){
                        cerr << "error: no response" << endl;
                        exit(1);
                }else cout << buffer << endl;
        }

        clearBuffer();
        return;
}

void Pop3Client::pop3authenticate(){

        //-- Username --//
        command = "USER "; command += username; command += ENDLINE;

        try{
                if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: an error ocurred while sending USER parameter" << endl;
                exit(1);
        }

        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                cerr << "error: no answer recieved" << endl;
                exit(1);
        }
        
        if(strstr(buffer,"+OK") != NULL){
                cout << buffer;
        }else{
                cerr << "error: an error ocurred while sending USER parameter" << endl;
                exit(1);
        }        
        clearBuffer();

        //-- Password --//
        command = "PASS "; command += password; command += ENDLINE; 

        try{
                if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: an error ocurred while sending PASS parameter" << endl;
                exit(1);
        }

        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                cerr << "error: no answer recieved" << endl;
                exit(1);
        }

        if(strstr(buffer,"+OK") != NULL){
                cout << buffer << endl;
        }else{
                cerr << "error: password: " << buffer << endl;
                exit(1);
        }        
        clearBuffer();
}

void Pop3Client::pop3stat(){

        command = "STAT "; command += ENDLINE;

        try{
                if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: an error ocurred while sending STAT parameter" << endl;
                exit(1);
        }

        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                cerr << "error: no answer recieved" << endl;
                exit(1);
        }

        if(strstr(buffer,"+OK") != NULL){
                if(strstr(buffer,"+OK 0 ") != NULL){
                        cout << "Downloaded 0 new messages." << endl;
                        exit(0);
                }else{
                        string messageNum(buffer,sizeof(buffer));
                        messageNum = messageNum.substr(4,messageNum.length());
                        messageNum = messageNum.substr(0,messageNum.find(' ')+1);
                        int mNum = stoi(messageNum);
                        for (int i=1; i <= mNum; i++){
                                pop3download(i);
                        }
                }

        }else{
                cerr << "error: STAT: " << buffer << endl;
                exit(1);
        }  
}

void Pop3Client::pop3download(int messageIndex){
        command = "RETR ";
        command += to_string(messageIndex); 
        command += ENDLINE;

        try{
                if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: an error ocurred while sending RETR parameter" << endl;
                exit(1);
        }

        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                cerr << "error: no answer recieved" << endl;
                exit(1);
        }
        saveMessage();

        //cout << buffer << endl;
        clearBuffer();

        //message deleting 
        if(deleteMessage){
                command = "DELE ";
                command += to_string(messageIndex); 
                command += ENDLINE;

                try{
                        if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
                }
                catch(int e){
                        cerr << "error: an error ocurred while sending DELE parameter" << endl;
                        exit(1);
                }

                try {
                        if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
                }
                catch(int e){
                        cerr << "error: no answer recieved" << endl;
                        exit(1);
                }
                clearBuffer();
                //cerr << "error: DELE " << to_string(messageIndex) << ": " << buffer << endl;

        }
}

void Pop3Client::pop3disconnect() {
        command = "QUIT"; command += ENDLINE;

        try{
                if(BIO_write(bio,command.c_str(),command.length()) <= 0) throw -1;
        }
        catch(int e){
                cerr << "error: an error ocurred while sending QUIT parameter" << endl;
                exit(1);
        }
        BIO_free_all(bio);

        if(encryptedComm){
                SSL_CTX_free(ctx);
        }
}

// ./popcl 172.26.144.1 -p 110 -a auth_file o -output_dir