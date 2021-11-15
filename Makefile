CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pthread -pedantic
LDFLAGS = -L/usr/include/openssl -L/usr/lib/ssl -L/usr/include/crypto++ 
LDLIBS = -lssl -lcrypto 

popcl: popcl.o popHeader.o
	g++ -std=c++17 -Wall -Wextra -pthread -pedantic popcl.o popHeader.o -o popcl -lssl -lcrypto

popcl.o: popcl.cpp
	g++ -std=c++17 -Wall -Wextra -pthread -pedantic -c popcl.cpp -o popcl.o -lssl -lcrypto

popHeader.o: popHeader.cpp popHeader.h
	g++ -std=c++17 -Wall -Wextra -pthread -pedantic -c popHeader.cpp -o popHeader.o -lssl -lcrypto

clean:
	rm *.o popcl
