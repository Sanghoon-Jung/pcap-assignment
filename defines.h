#pragma once
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/in.h>
#include <string>
#define ETH_HLEN        14
#define MACFORM         18
#define IPFORM          16
#define DATAFORM        48
#define MAX_DATA_BYTE   16
using namespace std;

typedef struct libnet_ethernet_hdr eth;
typedef struct libnet_ipv4_hdr ipv4;
typedef struct libnet_tcp_hdr tcp;

class pkt_info{
    private:
        eth* eth_hdr;
        ipv4* ip_hdr;
        tcp* tcp_hdr;
        
        uint8_t eth_hdr_len, ip_hdr_len, tcp_hdr_len;
        uint16_t payload_len;
        
        char src_mac[MACFORM], dst_mac[MACFORM];
        char src_ip[IPFORM], dst_ip[IPFORM];
        in_addr_t src_port, dst_port;
        uint8_t* databuf;
        char data[DATAFORM];

        void get_mac(uint8_t* addr, char* mac);
        void get_ip(struct in_addr* addr, char* ip);
        char* read_data(char* data);
        void eth_info(const u_char* eth_pkt);
        void ip_info(const u_char* ip_pkt);
        void tcp_info(const u_char* tcp_pkt);
        void printinfo();

    public:
        pkt_info(){ };
        void printpacket(const u_char* packet);
};