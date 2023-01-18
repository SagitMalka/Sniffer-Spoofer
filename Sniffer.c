#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <string.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *, int);
void print_data(const u_char *, int );

FILE *logfile;
struct sockaddr_in source, destination;


int main(int argc, char *argv[]){
    pcap_if_t *device, *handle;
    char error_buffer[PCAP_ERRBUF_SIZE], *device_name;
//    pcap_t ;
//    const u_char *packet;
//    struct pcap_pkthdr packet_header;
//    int packet_count_limit = 1;
//    int timeout_limit = 10000;
//
//    device = pcap_lookupdev(error_buffer);
//    if(device == NULL){
//        printf(stderr, "couldn't find\n");
//        return 2;
//    }
//    printf("device: %s\n", device);
//
//
//
    /**OPENING THE DEVICE FOR SNIFFING*/
    handle = pcap_open_live(device_name, 65536, 1,0,error_buffer);
    if(handle == NULL){
        printf(stderr, "couldn't open device %s : %s\n", device, error_buffer);
        return (2);
    }
    logfile = fopen("log.txt", "w");
    if(logfile == NULL){
        printf("unable to create file");
    }
    /**PUT DEVICE IN SNIFF LOOP*/
    pcap_loop(handle, -1, process_packet, NULL);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
    int size = header ->len;

    /**get ip header part*/
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    if (iph -> protocol) {
            print_tcp_packet(buffer, size);
    }
}
void print_ethernet_header(const u_char *Buffer, int size){
    struct ethhdr *ethheader = (struct ethhdr *)Buffer;
    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile, "source_ip: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethheader->h_source[0] , ethheader->h_source[1] , ethheader->h_source[2] , ethheader->h_source[3] , ethheader->h_source[4] , ethheader->h_source[5] );
    fprintf(logfile, "dest_ip: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \\n", ethheader->h_dest[0] , ethheader->h_dest[1] , ethheader->h_dest[2] , ethheader->h_dest[3] , ethheader->h_dest[4] , ethheader->h_dest[5]);
    fprintf(logfile, "protocol type: %u \n", (unsigned short )ethheader->h_proto);
}

void print_ip_header(const u_char *Buffer, int size){
    unsigned short ipheader_len;
    struct iphdr *iphdr = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    ipheader_len = iphdr->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iphdr->saddr;

    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = iphdr->daddr;

    fprintf(logfile, "source_ip: %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "dest_ip: %s\n", inet_ntoa(destination.sin_addr));
}
void print_tcp_packet(const u_char *Buffer, int size){
    unsigned short ipheaderlen;
    struct iphdr *iphdr =  (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    ipheaderlen = iphdr->ihl*4;

    struct tcphdr *tcphdr = (struct tcphdr*)(Buffer + sizeof(struct ethhdr));
    int header_size = sizeof(struct  ethhdr) + ipheaderlen + tcphdr->doff*4;
    fprintf(logfile, "\n\n TCP Packet\n");
    print_ip_header(Buffer, size);

    fprintf(logfile, "source_port: %u\n", ntohs(tcphdr->source));
    fprintf(logfile, "dest_port: %u\n", ntohs(tcphdr->dest));
    fprintf(logfile, "timestamp: \n");
    fprintf(logfile, "toatl_length: %d DWORDS or %d BYTES\n",(unsigned int)tcphdr->doff,(unsigned int)tcphdr->doff*4);
}