CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall
LDFLAGS ?= -pthread -lrt
SRC=aesdsocket.c
TARGET=aesdsocket

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
clean:
	rm -f *.o $(TARGET)
