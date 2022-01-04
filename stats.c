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

typedef struct arp_hdr
{
    u_short hard_type;
    u_short prot_type;
    u_short hard_len:2;
    u_short prot_len:2;
    u_short opcode;
    u_char s_mac[6];
    u_char sourceIP[4];
    u_char d_mac[6];
    u_char destIP[4];
}arp_hdr;
arp_hdr *arp;

void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content){
    int *id=(int *)arg;//記錄包ID
    printf("id=%d\n",++(*id));

    printf("Packet length : %d\n",packet_header->len);
    printf("Number of bytes : %d\n",packet_header->caplen);
    printf("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    int i;
    for(i=0;i<packet_header->caplen;i++){
        printf(" %02x",packet_content[i]);
        if((i+1)%16==0){
            printf("\n");
        }
    }
    printf("\n\n");
}


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
    if(strcmp(argv[1],"ens33")!=0){
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
        src_ip\t \
        dst_ip\t \
        protocol\t \
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
                printf(" %d.%d.%d.%d\t \
                    %d.%d.%d.%d\t" \
                    ,ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3] \
                    ,ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3] \
                );

                if(ip->protocol==6){
                    tcp=(tcp_hdr*)(packet+eth_len+ip_len);
                    printf("TCP\t \
                    %u\t%u\t" \
                    ,ntohs(tcp->sport),ntohs(tcp->dport) \
                    );
                }
                else if(ip->protocol==17){
                    udp=(udp_hdr*)(packet+eth_len+ip_len);
                    printf("UDP\t \
                    %u\t%u\t" \
                    ,ntohs(udp->sport),ntohs(udp->dport) \
                    );
                }
                else if(ip->protocol==89){
                    printf("OSPF\t-\t-\t");
                }
            }
            else if(ntohs(ethernet->eth_type)==0x0806){
                arp=(arp_hdr*)(packet+eth_len);
                printf(" %d.%d.%d.%d\t \
                    %d.%d.%d.%d\t \
                    -\t-\t" \
                    ,arp->sourceIP[0],arp->sourceIP[1],arp->sourceIP[2],arp->sourceIP[3] \
                    ,arp->destIP[0],arp->destIP[1],arp->destIP[2],arp->destIP[3] \
                );
            }
            else{
                printf("IP之外：%d",ntohs(ethernet->eth_type));
            }
            printf("\n");
        
        }
    }
    else if(strcmp(argv[1],"ens33")==0){
        char *dev,errbuf[1024];

        dev=argv[1];
        struct in_addr addr;
        bpf_u_int32 ipaddress, ipmask;
        char *dev_ip,*dev_mask;
        pcap_t *pcap_handle=pcap_open_live(dev,65535,1,0,errbuf);
        if(pcap_lookupnet(dev,&ipaddress,&ipmask,errbuf)==-1){
            printf("%s\n",errbuf);
            return 0;
        }

        addr.s_addr=ipaddress;
        dev_ip=inet_ntoa(addr);
        printf("ip address : %s\n",dev_ip);

        addr.s_addr=ipmask;
        dev_mask=inet_ntoa(addr);
        printf("netmask : %s\n",dev_mask);

        printf("---------packet--------\n");
        int id=0;//傳入回調函數記錄ID
        if(pcap_loop(pcap_handle,10,pcap_callback,(unsigned char *)&id)<0){//接收十個數據包
            printf("error\n");
            return 0;
        }

        pcap_close(pcap_handle);
    }
    /*opening trace file*/
    
}
