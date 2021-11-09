/**
 * @author David Svaty (xsvaty01)
 * @file popcl.cpp
 * @date 
 * 
 * This is a symple POP3 client.
 * For more documentation, please read manual.pdf and README files.
 * 
 */

#include <iostream>
#include <stdlib.h>
#include <stdbool.h>
#include <string>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "popHeader.h"

using namespace std;
using namespace pop3cl;

int main(int argc, char* argv[]) {

    if(argc == 1){
        cerr << "No arguments, type 'popcl -h' for manual" << endl;
        exit(-1);
    }


    pop3cl::Pop3Client client(argv[1]);

    /**
     *  Parameter switch 
     *  Mandatory parameters:  <server>, -a <auth_file>, -o <out_dir> 
     */
    int opt;
    while((opt = getopt(argc, argv, "hp:TSc:C:dna:o:")) != -1) {
        switch(opt) {

            case 'h':
                cout << "Usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>" << endl;
                exit(0);
                break;

            case 'p':
                client.serverPort = stoi(optarg);
                continue;

            case 'T':
                client.encryptedComm = true;
                continue;

            case 'S':
                client.encryptedSTLS = true;    
                continue;

            case 'C':
                client.certificate.certificatePathGiven = true;
                client.certificate.certificatePath = optarg;
                if (client.certificate.certificatePath == NULL) {
                    cerr << "error: cannot open certificate file" << endl;
                    exit(1);    
                }
                continue;

            case 'c':
                client.certificate.certificateGiven = true;
                client.certificate.certificateFile = optarg;
                if (client.certificate.certificateFile == NULL) {
                    cerr << "error: cannot open certificate file" << endl;
                    exit(1);    
                }
                continue;

            case 'd':
                client.deleteMessage = true;
                continue;

            case 'n':
                client.newMsgMode = true;        
                continue;

            case 'a':
                client.authentisation.authGiven = true;
                client.authentisation.authFileName = optarg;
                client.setUser();
                continue;

            case 'o':
                client.output.outGiven = true;
                client.output.outDir = optarg;
                continue;

            case '?': continue;
            default: break;
        }

    }
    /**
     * Mandatory parameters check 
    */
    if (!client.authentisation.authGiven) {
        cerr << "error: authentisation file not given" << endl;
        exit(1);
    }
    if (!client.output.outGiven) {
        cerr << "error: output file not given" << endl;
        exit(1);
    }

    client.pop3connect();
    client.pop3authenticate();
    client.pop3stat();
    client.pop3disconnect();
    return 0;
}