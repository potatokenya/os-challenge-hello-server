.RECIPEPREFIX := >

CC = gcc
CFLAGS = -Wall -Wextra -O2

.PHONY: all clean

all: server

server: server.c lonesha256.h
>$(CC) $(CFLAGS) server.c -o server

clean:
>rm -f server