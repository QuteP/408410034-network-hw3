#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> 
#include <time.h>

typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;
ip_hdr *ip;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;
tcp_hdr *tcp;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;
udp_hdr *udp;


int main(int argc, char** argv){

    pcap_t *pcap;
    char errbuf [PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    struct pcap_pkthdr header;

    u_int eth_len=sizeof(struct eth_hdr);
    u_int ip_len=sizeof(struct ip_hdr);
    u_int tcp_len=sizeof(struct tcp_hdr);
    u_int udp_len=sizeof(struct udp_hdr);


    if ( argc != 2 )
    {
        printf("\n\t\t Incorrect number of arguments provided");
        printf("\n\t\t Command format <<packet_headers.c>> <<capture1.pcap>>");
        exit(0);
    }


    /*opening trace file*/
    if ((pcap = pcap_open_offline(argv[1],errbuf)) == NULL){
        fprintf(stderr, "cant read file %s : %s\n",
                argv[0],errbuf);
        exit(1);
    }
    printf("packet_num\t \
    timestamp\t \
    len\t \
    cap_len\t \
    src_mac\t \
    dst_mac\t \
    type\t \
    protocol\t \
    src_ip\t \
    dst_ip\t \
    src_port\t \
    dst_port\n");

    /* reading packets */
    for (int i = 0; (packet = pcap_next(pcap,&header)) != NULL; i++){

        /*ethernet map */
        ethernet = (eth_hdr*)packet;

        printf("%d\t%s\t%d\t%d\t \
        %02x-%02x-%02x-%02x-%02x-%02x\t \
        %02x-%02x-%02x-%02x-%02x-%02x\t \
        %u\t \
        ", \
        i, \
        ctime((const time_t*)&(header.ts.tv_sec)), \
        header.len, \
        header.caplen, \
        ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5], \
        ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5], \
        ntohs(ethernet->eth_type) \
        );
        if(ntohs(ethernet->eth_type)==0x0800){
            ip=(ip_hdr*)(packet+eth_len);
            if(ip->protocol==0){
                printf("IPv4\t \
                %d.%d.%d.%d\t \
                %d.%d.%d.%d\t \
                -\t-\t" \
                ,ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3] \
                ,ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3] \
                );
            }
            else if(ip->protocol==6){
                tcp=(tcp_hdr*)(packet+eth_len+ip_len);
                printf("TCP\t \
                %d.%d.%d.%d\t \
                %d.%d.%d.%d\t \
                %u\t%u\t" \
                ,ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3] \
                ,ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3] \
                ,tcp->sport,tcp->dport \
                );
            }
            else if(ip->protocol==17){
                udp=(udp_hdr*)(packet+eth_len+ip_len);
                printf("UDP\t \
                %d.%d.%d.%d\t \
                %d.%d.%d.%d\t \
                %u\t%u\t" \
                ,ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3] \
                ,ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3] \
                ,udp->sport,udp->dport \
                );
            }
            else{
                printf("未知的：%d",ip->protocol);
            }
        }
        else{
            printf("IP之外：%d",ntohs(ethernet->eth_type));
        }
        printf("\n");
    
    }
}
