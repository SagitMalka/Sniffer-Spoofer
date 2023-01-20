CFLAGS = -Wall

all: sniffer
sniffer: Sniffer.c
	gcc $(CFLAGS) Sniffer.c -o sniffer -lpcap
	
clean:
	rm -f *.o sniffer log.txt
