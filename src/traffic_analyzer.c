#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <time.h>

#define PACKET_FILE_PATH "./exec/packets.csv"

// Convert protocol number to name
const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "OTHER";
    }
}

// Determine packet direction by checking if source IP is local (approx)
// Here just a placeholder, since proper direction detection is complex.
// For now, always "Unknown".
const char* packet_direction() {
    return "Unknown";
}

// TCP flag string builder
void get_tcp_flags(uint8_t flags, char *buf) {
    buf[0] = '\0';
    if (flags & TH_SYN) strcat(buf, "SYN|");
    if (flags & TH_ACK) strcat(buf, "ACK|");
    if (flags & TH_FIN) strcat(buf, "FIN|");
    if (flags & TH_RST) strcat(buf, "RST|");

    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '|') {
        buf[len-1] = '\0'; // Remove trailing '|'
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    FILE *fp = (FILE *)args;

    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        int ip_header_len = ip_header->ip_hl * 4;

        char *src_ip = inet_ntoa(ip_header->ip_src);
        char *dst_ip = inet_ntoa(ip_header->ip_dst);

        const char *proto_name = protocol_name(ip_header->ip_p);
        int len = header->len;
        int caplen = header->caplen;
        int ttl = ip_header->ip_ttl;

        // Format MAC addresses
        char src_mac[18], dst_mac[18];
        snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth_header->ether_shost[0], eth_header->ether_shost[1],
                 eth_header->ether_shost[2], eth_header->ether_shost[3],
                 eth_header->ether_shost[4], eth_header->ether_shost[5]);

        snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth_header->ether_dhost[0], eth_header->ether_dhost[1],
                 eth_header->ether_dhost[2], eth_header->ether_dhost[3],
                 eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

        // Packet direction
        const char *direction = packet_direction();

        // TCP/UDP/ICMP specifics
        uint16_t src_port = 0, dst_port = 0;
        uint32_t seq = 0, ack = 0;
        char tcp_flags[32] = "";

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);
            seq = ntohl(tcp_header->th_seq);
            ack = ntohl(tcp_header->th_ack);
            get_tcp_flags(tcp_header->th_flags, tcp_flags);
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
            src_port = ntohs(udp_header->uh_sport);
            dst_port = ntohs(udp_header->uh_dport);
        }

        // Get timestamp
        char timebuf[64];
        time_t local_tv_sec = header->ts.tv_sec;
        struct tm *ltime = localtime(&local_tv_sec);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", ltime);

        // Print summary to console
        printf("[%s] %s | %s:%d -> %s:%d | %s | Len: %d | TTL: %d | Seq: %u | Ack: %u | Flags: %s\n",
               timebuf, proto_name, src_ip, src_port, dst_ip, dst_port, direction,
               len, ttl, seq, ack, tcp_flags);

        // Write CSV: timestamp,srcMAC,dstMAC,srcIP,srcPort,dstIP,dstPort,proto,dir,flags,len,caplen,ttl,seq,ack
        fprintf(fp, "%s,%s,%s,%s,%u,%s,%u,%s,%s,%s,%d,%d,%d,%u,%u\n",
                timebuf, src_mac, dst_mac, src_ip, src_port, dst_ip, dst_port,
                proto_name, direction, tcp_flags, len, caplen, ttl, seq, ack);
        fflush(fp);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("\n[ERROR] Missing network interface name!\n");
        printf("Usage:\n  %s <interface>\n", argv[0]);
        printf("Example:\n  %s en0\n", argv[0]);
        return 1;
    }

    char *device = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    FILE *fp = fopen(PACKET_FILE_PATH, "a");
    if (fp == NULL) {
        perror("Could not open output file");
        return 1;
    }

    // If empty, write CSV header
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "Timestamp,SourceMAC,DestinationMAC,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,Direction,TCPFlags,OriginalLength,CapturedLength,TTL,Seq,Ack\n");
        fflush(fp);
    }

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        fclose(fp);
        return 2;
    }

    printf("Listening on %s... Press Ctrl+C to stop.\n", device);

    pcap_loop(handle, -1, packet_handler, (u_char *)fp);

    pcap_close(handle);
    fclose(fp);

    printf("Packet log written to %s\n", PACKET_FILE_PATH);

    return 0;
}
