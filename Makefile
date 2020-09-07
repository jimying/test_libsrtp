DEPS_DIR = ./build_libsrtp
CC = gcc
CFLAGS = -Wall -g
INC = -I $(DEPS_DIR)/include
LIBS = $(DEPS_DIR)/lib/libsrtp2.a

all: tst

clean:
	rm -f tst *.o

tst: test.c
	$(CC) $(CFLAGS) $(INC) $^ -o $@ $(LIBS)
