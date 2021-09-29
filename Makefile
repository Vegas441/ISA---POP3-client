CC = g++
CFLAGS = -std=c++17 -Wall -Wextra

popcl: popcl.o popHeader.o
	$(CC) $(CFLAGS) $^ -o $@

popcl.o: popcl.cpp
	$(CC) $(CFLAGS) -c $< -o $@

popHeader.o: popHeader.cpp popHeader.h
	$(CC) $(CFLAGS) -c $< -o $@	

clean:
	rm *.o popcl
