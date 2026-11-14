CC=gcc
CFLAGS=-Wall -Wextra -g
LIBS=-lpcap
SRCS=main.c decode.c connections.c stats.c names.c http.c security.c

sniffer: $(SRCS) sniffer.h
	$(CC) $(CFLAGS) $(SRCS) -o sniffer $(LIBS)

clean:
	rm -f sniffer
