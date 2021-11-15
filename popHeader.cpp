/**
 * @author David Svaty (xsvaty01)
 * @file popHeader.cpp
 * @date 15.11.2021
 */

#include <iostream>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <fstream>
#include <sstream>
#include <ctime>
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
        delMsgMode = false;
        newMsgMode = false;
        authentisation.authGiven = false;
        output.outGiven = false;        
        messagesDownloaded = 0;

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

bool Pop3Client::messageIsNew(string msg){
        time_t currTime = time(0);
        
        string msgDate = msg.substr(msg.find("Date: ")+6, string::npos);
                msgDate = msgDate.substr(msgDate.find(",")+2,msgDate.find("\n"));
        
        //puts message timestamp into correct format 
        struct tm tm;
        strptime(msgDate.c_str(), "%d %b %Y %T %Z", &tm);
        time_t msgTime = mktime(&tm);
        
        //if message is older than one day
        return difftime(currTime,msgTime) > 86400 ? false : true; 
}

bool Pop3Client::messageIsEnd(string msg){
        if(msg.find("\r\n.\r\n") != string::npos) return false;
        else return true;
}

string Pop3Client::formatMessage(string msg){
        return msg;
}

void Pop3Client::saveMessage(string msg){
        //msg = formatMessage(msg);
        
        string msgDate = msg.substr( msg.find("Date: ")+6 , string::npos );
                msgDate = msgDate.substr( 0 , msgDate.find("\n")+1);

        string msgSender = msg.substr( msg.find("From: ")+6 , string::npos ); 
                msgSender = msgSender.substr( 0 , msgSender.find("\n")+1);

        string msgReciever = msg.substr( msg.find("To: ")+4 , string::npos );
                msgReciever = msgReciever.substr( 0 , msgReciever.find("\n")+1);

        string msgSubject = msg.substr( msg.find("Subject: ")+9 , string::npos );
                msgSubject = msgSubject.substr( 0 , msgSubject.find("\n")+1);
        
        string msgId = msg.substr( msg.find("Message-ID: ")+12 , string::npos );
                msgId = msgId.substr( 0 , msgId.find("\n")+1);

        /**
         * Header extraction
         * continueMsg - shortened message string
         */
        string msgHeaders;
        {
                string continueMsg = msg.substr(msg.find(msgId, msgId.length()-1), string::npos);
                istringstream f(continueMsg);
                string line;
                getline(f,line);
                while(getline(f,line)){
                        if((int)line.find("Message-ID") != -1 || (int)line.find("To") != -1 || (int)line.find("From") != -1
                        || (int)line.find("Subject") != -1 || (int)line.find("Date") != -1)
                                continue;
                        else if(line.length() == 1) break;
                        else msgHeaders += line;
                }
        }        

        
        //Extracts message
        istringstream f(msg);
        string line;
        string msgContent;
        bool extract = false;
        while(getline(f,line)){
                //if(!messageIsEnd(line)) break; // !!!Treba aby fungovalo 

                if(extract)
                        msgContent += line;    

                if(line.length() == 1){ //if line is empty 
                        extract = true;        
                }
        }


        //Creates new file
        string fileName = output.outDir + "/" + msgId.substr(1,msgId.find("@")-1);
        ofstream msgFile (fileName);

        msgFile << "Date: " << msgDate;
        msgFile << "From: " << msgSender;
        msgFile << "To: " << msgReciever;
        msgFile << "Subject: " << msgSubject;
        msgFile << "ID: " << msgId;
        msgFile << msgHeaders;
        msgFile << "\n\n";
        msgFile << msgContent;

        msgFile.close();
}

void Pop3Client::deleteMessage(int messageIndex){
        command = "DELE ";
                command += to_string(messageIndex); 
                command += ENDLINE;

                pop3send(command);
                pop3read();
                pop3isOk();

                clearBuffer();
}

void Pop3Client::pop3send(string cmd){
        try{
                if(BIO_write(bio,cmd.c_str(),cmd.length()) <= 0) throw -1;
        }
        catch(int e){
                string param = cmd.substr(0,4);
                cerr << "error: an error ocurred while sending" << param << "parameter" << endl;
                exit(1);
        }
}

void Pop3Client::pop3read(){
        try {
                if(BIO_read(bio,buffer,BUFFSIZE) < 0) throw -1;
        }
        catch(int e){
                string param = command.substr(0,4);
                cerr << "error: " << param << ": no answer recieved" << endl;
                exit(1);
        }
}

void Pop3Client::pop3isOk(){
        if(strstr(buffer,"+OK") != NULL){
                //cout << buffer; // potom upravit
        }else{
                //tuto sa treba pozret pri DELE 
                if((int)command.find("DELE") != -1) return;
                cerr << "error: " << command << ": "<< buffer << endl;
                exit(1);
        }
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

        pop3read();
        pop3isOk();

        if(encryptedSTLS){
                command = "STLS"; command += ENDLINE;
                pop3send(command);
                pop3read();
                pop3isOk();
        }

        clearBuffer();
        return;
}

void Pop3Client::pop3authenticate(){

        //-- Username --//
        command = "USER "; command += username; command += ENDLINE;
        pop3send(command);

        pop3read();
        pop3isOk();        
        clearBuffer();

        //-- Password --//
        command = "PASS "; command += password; command += ENDLINE; 
        pop3send(command);
        pop3read();

        pop3isOk();        
        clearBuffer();
}

void Pop3Client::pop3stat(){

        command = "STAT "; command += ENDLINE;
        pop3send(command);
        pop3read();
        pop3isOk();

        if(strstr(buffer,"+OK 0") != NULL){
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
        cout << "Downloaded " << messagesDownloaded << " messages." << endl; 
}

void Pop3Client::pop3download(int messageIndex){
        command = "RETR ";
        command += to_string(messageIndex); 
        command += ENDLINE;

        pop3send(command);

        //read until end of message
        string msg;
        do{
                //cout << messageIsEnd(buffer) << endl;
                pop3read();
                msg += string(buffer);
                clearBuffer();
        }while(messageIsEnd(msg));

        //Scraps old messages if new message mode is on
        if((!newMsgMode) || (newMsgMode && messageIsNew(msg))){
                messagesDownloaded++;
                saveMessage(msg);
                clearBuffer();

                //message deleting 
                if(delMsgMode) deleteMessage(messageIndex);
        }
}

void Pop3Client::pop3disconnect() {

        command = "QUIT"; command += ENDLINE;
        pop3send(command);

        BIO_reset(bio);
        BIO_free_all(bio);

        if(encryptedComm || encryptedSTLS){      
                SSL_CTX_free(ctx);
        }

        buffer = NULL;
        free(buffer);
}

// ./popcl 172.26.144.1 -p 110 -a auth_file o -output_dir