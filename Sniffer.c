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



void PrintData (const u_char * data , int Size);
void print_the_packet(const u_char *buffer, int size);


FILE *logfile;
struct sockaddr_in source, dest;


struct iphdr *iphdr;
struct ethhdr *ethhdr;


struct myHeader
{
    u_int32_t timestamp;
    u_int16_t total_lenght;
    u_char saved : 3;
    u_char cache_flag : 1;
    u_char steps_flag : 1;
    u_char type_flag : 1;
    u_int16_t status_code : 10;
    u_int16_t cache_control;
    u_int16_t padding;
};
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int size = header->len;
        print_the_packet(packet, size);

}



int main() {
    printf("sup\n");

    /**SETTING THE DEVICE**/
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;


    char filter_exp[] = "ip proto 0x6";

    struct bpf_program bpfProgram;
    bpf_u_int32 net;
    struct bpf_program fp;


    /**OPENING THE DEVICE FOR SNIFFING**/
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Can't open enp0s3: %s\n", errbuf);
        return -1;
    }


    logfile = fopen("209294768_206477788.txt", "w");
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


void print_the_packet(const u_char *buffer, int size) {
    unsigned short ip_header_len;

    struct iphdr *iphdr1 = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    ip_header_len = iphdr1->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iphdr1->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iphdr1->daddr;



    struct tcphdr *tcphdr = (struct tcphdr *) (buffer + ip_header_len + sizeof(struct ethhdr));
    int header_size = sizeof(struct ethhdr) + ip_header_len + tcphdr->doff * 4;

    fprintf(logfile, "\ncaptured packet: \n");

    fprintf(logfile, " source ip: %s", inet_ntoa(source.sin_addr));
    fprintf(logfile, ", dest ip: %s\n", inet_ntoa(dest.sin_addr));
    fprintf(logfile, " source port: %u", ntohs(tcphdr->source));
    fprintf(logfile, " dest port: %u", ntohs(tcphdr->dest));
   struct myHeader *my_hdr = (struct myHeader *) (struct msghdr *) (buffer + header_size + ip_header_len +
                                                                    sizeof(struct ethhdr));
    fprintf(logfile, " timestamp: %u", my_hdr->timestamp);
    fprintf(logfile, " total_length: %u", my_hdr->total_lenght);
    fprintf(logfile, " cache_flag: %hu", (unsigned int )(my_hdr->cache_flag));
    fprintf(logfile, " steps_flag: %hu", (unsigned int )(my_hdr->steps_flag));
    fprintf(logfile, " type_flag: %hu", (unsigned int )(my_hdr->type_flag));
    fprintf(logfile, " status_code: %hu", (unsigned int )(my_hdr->status_code));
    fprintf(logfile, " cache_control: %hu", (unsigned int )(my_hdr->cache_control));

    fprintf(logfile , " Data Payload\n");
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
