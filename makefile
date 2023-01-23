all: sniffer spoofer gateway

sniffer: Sniffer.c
	gcc $(CFLAGS) Sniffer.c -o sniffer.o -lpcap
spoofer: Spoofer.c
	gcc -c Spoofer.c -o spoofer.o
gateway: Gateway.c
	gcc -c Gateway.c -o gateway.o
	
clean:
	rm -f *.o sniffer log.txt spoofer gateway
