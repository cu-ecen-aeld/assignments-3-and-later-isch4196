CC=gcc
CFLAGS=-ggdb -Wall
LDFLAGS=-lpthread
SRC=aesdsocket.c
TARGET=aesdsocket

all:
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(LDFLAGS) $(SRC) -o $(TARGET)
clean:
	rm -f *.o $(TARGET)
