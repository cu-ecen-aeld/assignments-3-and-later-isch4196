CC=gcc
CFLAGS= -Wall
LDFLAGS=-pthread -lrt
SRC=aesdsocket.c
TARGET=aesdsocket

all:
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
clean:
	rm -f *.o $(TARGET)
