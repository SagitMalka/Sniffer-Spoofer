all: sniffer spoofer gateway sniffspoof

sniffer: Sniffer.c
	gcc Sniffer.c -o sniffer -lpcap
spoofer: Spoofer.c
	gcc Spoofer.c -o spoofer
gateway: Gateway.c
	gcc Gateway.c -o gateway
sniffspoof: SniffAndSpoof.c
	gcc SniffAndSpoof.c -o sniffspoof -lpcap
	
clean:
	rm -f *.o sniffer 209294768_206477788.txt spoofer gateway
