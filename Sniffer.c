#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>
#define SNAPLEN 1518


/**TO DO
 * print packet info using packet handler
 * all fields required
 * */
//void print_pcap_packet(const u_char *, int);

void print_ip_packet(const u_char *, int);
void PrintData (const u_char * data , int Size);
void print_tcp_packet(const u_char *buffer, int size);
//void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

FILE *logfile;
struct sockaddr_in source, dest;
//struct pcap_pkthdr *header;

struct iphdr *iphdr;
struct ethhdr *ethhdr;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int size = header->len;

    struct iphdr *iphdr1 = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if(iphdr1->protocol == 0){

    }
    print_tcp_packet(packet, size);

    struct ether_header *etherHeader;
    etherHeader = (struct ether_header *) packet;
    if (ntohs(etherHeader->ether_type) != ETHERTYPE_IP) {
        return;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        return;
    }
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*tcp_header + 12) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen - total_headers_size;
    payload = packet + total_headers_size;



    return;
}


//void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
//{
//    int i;
//
//    fprintf(logfile,"Packet of length %d:\n", header->len);
//    for (i = 0; i < header->len; i++) {
//        fprintf(logfile, "%02x ", packet[i]);
//    }
//    fprintf(logfile, "\n");
//}

int main() {
    printf("sup\n");

    /**SETTING THE DEVICE**/
//    char *dev = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;


    char filter_exp[] = "ip proto 0x6";

    struct bpf_program bpfProgram;
    bpf_u_int32 net;
    struct bpf_program fp;


    /**OPENING THE DEVICE FOR SNIFFING**/
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
//        printf("error: \"%s\"\n", errbuf);
        fprintf(stderr, "Can't open enp0s3: %s\n", errbuf);
        return -1;
    }


    logfile = fopen("log.txt", "w");
    if (logfile == NULL) {
        fprintf(stderr, "Can't open file: %s\n", errbuf);
        return -1;
    }
    printf("1\n");
    /**FILTERING TRAFFIC**/
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    pcap_setfilter(handle, &bpfProgram);
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    /**CAPTURE PACKETS**/
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&bpfProgram);
    pcap_close(handle);
    fclose(logfile);
    return (0);
}

void print_ip_packet(const u_char *buffer, int size) {
    unsigned short ip_header_len;
    struct iphdr *iphdr1 = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    ip_header_len = iphdr1->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iphdr1->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iphdr1->daddr;

    fprintf(logfile, " source ip: %s", inet_ntoa(source.sin_addr));
    fprintf(logfile, ", dest ip: %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const u_char *buffer, int size) {
    unsigned short ip_header_len;

    struct iphdr *iphdr1 = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    ip_header_len = iphdr1->ihl * 4;

    struct tcphdr *tcphdr = (struct tcphdr *) (buffer + ip_header_len + sizeof(struct ethhdr));
    int header_size = sizeof(struct ethhdr) + ip_header_len + tcphdr->doff * 4;

    fprintf(logfile, "\ncaptured packet: \n");

    print_ip_packet(buffer, size);

    fprintf(logfile, " source port: %u", ntohs(tcphdr->source));
    fprintf(logfile, " dest port: %u\n", ntohs(tcphdr->dest));
    fprintf(logfile, " timestamp: ", ntohl(tcphdr->th_seq));
    


    fprintf(logfile , "IP Header\n");
    PrintData(buffer,ip_header_len);

    fprintf(logfile , "TCP Header\n");
    PrintData(buffer+ip_header_len,tcphdr->doff*4);

    fprintf(logfile , "Data Payload\n");
    PrintData(buffer + header_size , size - header_size );
}
void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
        fprintf(logfile , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                    fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}
