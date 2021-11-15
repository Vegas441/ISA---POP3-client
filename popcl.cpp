/**
 * @author David Svaty (xsvaty01)
 * @file popcl.cpp
 * @date 15.11.2021
 * 
 * This is a symple POP3 client.
 * For more documentation, please read manual.pdf and README files.
 * 
 */

#include <iostream>
#include <stdlib.h>
#include <stdbool.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "popHeader.h"

using namespace std;
using namespace pop3cl;

int main(int argc, char* argv[]) {

    if(argc == 1){
        cerr << "No arguments, type 'popcl -h' for manual" << endl;
        exit(-1);
    }

    // Print help
    if(!strcmp(argv[1],"-h")){
            cout << "Usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>" << endl;
            exit(0);    
    }

    pop3cl::Pop3Client client(argv[1]);

    /**
     *  Parameter switch 
     *  Mandatory parameters:  <server>, -a <auth_file>, -o <out_dir> 
     */
    for(int i=2; i < argc; i++){
        char* arg = argv[i];

        if(!strcmp(arg,"-p")){
            i++;
            client.serverPort = atoi(argv[i]);
            continue;
        }
        else if(!strcmp(arg,"-T")){
            client.encryptedComm = true;
            continue;
        }
        else if(!strcmp(arg,"-S")){
            client.encryptedSTLS = true;
            continue;
        }
        else if(!strcmp(arg,"-C")){
            i++;
            client.certificate.certificatePathGiven = true;
            client.certificate.certificatePath = argv[i];
            if (client.certificate.certificatePath == NULL) {
               cerr << "error: cannot open certificate file" << endl;
                exit(1);    
            }
            continue;
        }
        else if(!strcmp(arg,"-c")){
            i++;
            client.certificate.certificateGiven = true;
            client.certificate.certificateFile = argv[i];
            if (client.certificate.certificateFile == NULL) {
                cerr << "error: cannot open certificate file" << endl;
                exit(1);    
            }
            continue;
        }
        else if(!strcmp(arg,"-d")){
            client.delMsgMode = true;
            continue;
        }    
        else if(!strcmp(arg,"-n")){
            client.newMsgMode = true;
            continue;
        }
        else if(!strcmp(arg,"-a")){
            i++;
            client.authentisation.authGiven = true;
            client.authentisation.authFileName = argv[i];
            client.setUser();
            continue;
        }
        else if(!strcmp(arg,"-o")){
            i++;
            client.output.outGiven = true;
            client.output.outDir = argv[i];
            continue;
        }
        else{
            cerr << "error: " << argv[i] << ": unknown parameter" << endl; 
            exit(1);
        }
    }

    if (!client.authentisation.authGiven) {
        cerr << "error: [-a]: authentisation file not given" << endl;
        exit(1);
    }
    if (!client.output.outGiven) {
        cerr << "error: [-o]: output file not given" << endl;
        exit(1);
    }

    if(client.encryptedComm && client.encryptedSTLS){
        cerr << "error: [-T|-S]: both parameters in the same time are forbidden" << endl;
        exit(1);
    }

    if((client.certificate.certificateGiven || client.certificate.certificatePathGiven) && (!client.encryptedComm && !client.encryptedSTLS)){
        cerr << "error: [-c|-C]: not using encrypted connection" << endl;
        exit(1);
    }

    //if(client.encryptedSTLS && !client.certificate.certificateGiven && !client.certificate.certificatePathGiven){
    //    cerr << "error: [-S]: certificate not given" << endl;
    //    exit(1);
    //}

    client.pop3connect();
    client.pop3authenticate();
    client.pop3stat();
    client.pop3disconnect();

    return 0;
}