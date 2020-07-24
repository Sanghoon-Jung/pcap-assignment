#include <pcap.h>
#include <stdio.h>
#include <memory>
#include "defines.h"
#include "etc_func.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handler == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handler, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handler));
            break;
        }
        
        unique_ptr<pkt_info> info(new pkt_info);
        info->printpacket(packet);
    }

    pcap_close(handler);
}