# Simple POP3 client with STLS support 
Author: David Svaty
Login: xsvaty01
Deadline: 15.11.2021

## Usage
popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>

### Parameters
-p <port> ->        Specifies a port number  
-T ->               Encrypts entire communication 
-S ->               Encrypts communication with STLS 
-c <certfile> ->    Defines certificate file
-C <certaddr> ->    Defines certificate path 
-d ->               Deletes downloaded messages
-n ->               Only downloads new messages   
-a <auth_file> ->   Sets file with user credentials 
-o <output_dir ->   Sets output directory

### Example o usage
./popcl pop.seznam.cz -p 110 -T -a auth_file -o output_dir
./popcl 10.10.10.1 -p 1234 -T -n -o maildir -a cred
./popcl eva.fit.vutbr.cz -o maildir -a cred -T -c /dev/null -C /dev/null