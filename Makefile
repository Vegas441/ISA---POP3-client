CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pthread -pedantic
LDFLAGS = -L/usr/include/openssl -L/usr/lib/ssl -L/usr/include/crypto++ 
LDLIBS = -lssl -lcrypto 

popcl: popcl.o popHeader.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

popcl.o: popcl.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS) $(LDLIBS)

popHeader.o: popHeader.cpp popHeader.h
	$(CC) $(CFLAGS) -c $< -o $@	$(LDFLAGS) $(LDLIBS)

clean:
	rm *.o popcl
