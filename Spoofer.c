#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define SOURCE_IP "10.0.0.45"

unsigned short calculate_checksum(unsigned short *buffer, int length);


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

    struct ip *pIp = (struct ip *)buffer;
    pIp->ip_v = 4;
    pIp->ip_hl = 5;
    pIp->ip_ttl = 20;
    pIp->ip_src.s_addr = inet_addr(SOURCE_IP);
//    ip_header->ip_dst.s_addr = inet_addr("10.0.2.5");
    pIp->ip_p = IPPROTO_ICMP;
    pIp->ip_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    struct icmp *pIcmp = (struct icmp *)(buffer + sizeof(struct ip));
    pIcmp->icmp_type = 8;
    pIcmp->icmp_cksum = 0;
    pIcmp->icmp_cksum = calculate_checksum((unsigned short *)pIcmp, sizeof(struct icmp));

    if(sendto(fd, &buffer, pIp->ip_len, 0, (struct sockaddr *)&sockaddrIn, sizeof (sockaddrIn)) < 0){
        perror("sendto faild \n");
        exit(-1);
    }
}

/** Compute checksum (RFC 1071) **/
unsigned short calculate_checksum(unsigned short *buffer, int length) {
    int nleft = length;
    int sum = 0;
    unsigned short *w = buffer;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    /** add back carry outs from top 16 bits to low 16 bits **/
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
