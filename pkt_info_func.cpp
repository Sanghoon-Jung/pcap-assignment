#include "defines.h"

void pkt_info::get_mac(uint8_t* addr, char* mac){
    char* p = mac;
    for(int i = 0; i < ETHER_ADDR_LEN; i++)
        p += sprintf(p, "%02x:", addr[i]);
    *(p-1) = '\0';
}

void pkt_info::get_ip(struct in_addr* addr, char* ip){
    char* p = ip;
    uint8_t* byte = (uint8_t*) &addr->s_addr;
    for(int i = 0; i < 4; i++)
        p += sprintf(p, "%u.", *(byte + i));
    *(p-1) = '\0';
}

char* pkt_info::read_data(char* data){
    char* p = data;
    uint16_t data_len = this->payload_len;
    if(data_len == 0) p += sprintf(p, "\bNo data");
    else{
        for(int i = 0; i < MAX_DATA_BYTE && data_len != 0; data_len--, i++)
            p += sprintf(p, "%02x ", *(this->databuf + i));
        *(p-1) = '\0';
    }
    return data;
}

void pkt_info::eth_info(const u_char* eth_pkt){
    this->eth_hdr = (eth*) eth_pkt;
    get_mac(this->eth_hdr->ether_shost, this->src_mac);
    get_mac(this->eth_hdr->ether_dhost, this->dst_mac);
    this->eth_hdr_len = ETH_HLEN;
}

void pkt_info::ip_info(const u_char* ip_pkt){
    this->ip_hdr = (ipv4*) ip_pkt;
    get_ip(&this->ip_hdr->ip_src, this->src_ip);
    get_ip(&this->ip_hdr->ip_dst, this->dst_ip);
    this->ip_hdr_len = this->ip_hdr->ip_hl * 4;
}

void pkt_info::tcp_info(const u_char* tcp_pkt){
    this->tcp_hdr = (tcp*) tcp_pkt;
    this->src_port = ntohs(this->tcp_hdr->th_sport);
    this->dst_port = ntohs(this->tcp_hdr->th_dport);
    this->tcp_hdr_len = this->tcp_hdr->th_off * 4;
    this->databuf = (uint8_t*)this->tcp_hdr + this->tcp_hdr_len;
}

void pkt_info::printinfo(){
    static uint64_t tcp_pkt_cnt = 0;
    this->payload_len = ntohs(this->ip_hdr->ip_len) - this->ip_hdr_len - this->tcp_hdr_len;

    printf("@ TCP pkt# = %d\n", ++tcp_pkt_cnt);
    printf("------- ETH header info -------\n");
    printf("1. src mac: %s\n", this->src_mac);
    printf("2. dst mac: %s\n", this->dst_mac);
    printf("\n------- IP header info -------\n");
    printf("1. src ip: %s\n", this->src_ip);
    printf("2. dst ip: %s\n", this->dst_ip);
    printf("\n------- TCP header info -------\n");
    printf("1. src port: %u\n", this->src_port);
    printf("2. dst port: %u\n", this->dst_port);
    printf("\n------- TCP Payload info -------\n");
    printf("data(16 byte): ");
    printf("%s\n\n\n", read_data(this->data));
}

void pkt_info::printpacket(const u_char* packet){
    eth_info(packet);
    
    if(ntohs(this->eth_hdr->ether_type) == ETHERTYPE_IP)
        ip_info(packet += this->eth_hdr_len);
    
    if(this->ip_hdr->ip_p == IPPROTO_TCP){
        tcp_info(packet += this->ip_hdr_len);
        printinfo();
    }
}