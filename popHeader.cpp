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

using namespace pop3cl;
using namespace std;

Pop3Client::Pop3Client(const char *addr){

        buffer = (char*)malloc(BUFFSIZE);
        serverAddr = addr;
        serverPort = 110;
        encryptedComm = false;
        encryptedSTLS = false;
        certificate.certificateGiven = false;
        deleteMessage = false;
        newMsgMode = false;
        authentisation.authGiven = false;
        output.outGiven = false;        

        hostname = (char *)malloc((strlen(serverAddr)+6*(sizeof(char)))*sizeof(char));
        strcpy(hostname,serverAddr);
        strcat(hostname,":");

        char *port = (char*)malloc(5*sizeof(char));
        sprintf(port,"%d",serverPort);
        strcat(hostname,port);
}

void Pop3Client::SSLinit(){
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
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
        else {
                SSL_CTX_set_default_verify_paths(ctx);
        }
}

void Pop3Client::pop3connect(){

        //SSL initialization
        SSLinit();

        //toto presunut ako parameter classy
        SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
        SSL *ssl;

        bio = BIO_new_ssl_connect(ctx);
        BIO_get_ssl(bio, & ssl);
        SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
        BIO_set_conn_hostname(bio,hostname);
        //SSL_CTX_set_timeout(ctx,5);


        try {
                if((bio = BIO_new_connect(hostname)) == NULL) throw -1;
        }
        catch(int e){
                cerr << "error: connection failed" << endl;
                exit(1);
        }

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
                cout << buffer << endl;
        }else{
                cerr << "error: server not responding" << endl;
                exit(1);
        }
}

void Pop3Client::pop3authenticate(){

        //-- Username --//
        strcpy(buffer,"USER ");
        strcat(buffer,username.c_str());

        try{
                if(BIO_write(bio,buffer,BUFFSIZE) <= 0) throw -1;
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
                cout << buffer << endl;
        }else{
                cerr << "error: an error ocurred while sending USER parameter" << endl;
                exit(1);
        }        


        //-- Password --//
        strcpy(buffer,"PASS ");
        strcat(buffer,password.c_str());

        try{
                if(BIO_write(bio,buffer,BUFFSIZE) <= 0) throw -1;
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
                cout << buffer << endl;
        }else{
                //cout << buffer << endl;
                cerr << "error: incorrect password" << endl;
                exit(1);
        }        
}

