#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define SOURCE_IP "10.0.0.45"
// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short *paddress, int len);


int main() {
    int fd;
    struct sockaddr_in sockaddrIn;
    char buffer[1500];
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(socket < 0){
        perror("can't open socket");
        exit(-1);
    }

    sockaddrIn.sin_family = AF_INET;

    struct iphdr *ip_header = (struct iphdr *)buffer;
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->ttl = 20;
    ip_header->saddr = inet_addr(SOURCE_IP);
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->tot_len = htons(sizeof(struct iphdr)+ sizeof(struct icmphdr));

    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + sizeof(ip_header));
    icmp_header->type = 8;

    icmp_header->checksum =0;

    if(sendto(fd, &buffer, ip_header->tot_len, 0, (struct sockaddr *)&sockaddrIn, sizeof (sockaddrIn)) < 0){
        perror("sendto faild \n");
        exit(-1);
    }
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
