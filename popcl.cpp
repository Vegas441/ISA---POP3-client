/**
 * @author David Svaty (xsvaty01)
 * @date 
 * 
 * This is a symple POP3 client.
 * For more documentation, please read manual.pdf and README files.
 * 
 */

#include <iostream>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include "popHeader.h"

using namespace std;
using namespace pop3cl;

int main(int argc, char* argv[]) {

    if(argc == 1){
        fprintf(stderr,"No arguments, type 'popcl --help' for manual");
        exit(-1);
    }
    string serverAddr = argv[1]; 
    
    while(int opt = getopt(argc, argv, "p:TSc:C:dna:o:") != -1) {
        switch(opt) {
            

            default: break;
        }


    }
    return 0;
}