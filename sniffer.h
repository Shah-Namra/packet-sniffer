#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>

// Max connection table can hold
#define MAX_CONNS 100

// One TCP connection. Both directions of the same connection share one entry
// The two endpoints are stored in sorted order (lower IP/port first)
typedef struct
{
    unsigned char src_ip[4];   
    unsigned char dst_ip[4];  
    int src_port;             // 
    int dst_port;             // 
    int in_use;               // 1 if this slot holds a connection
    int syn_seen;             // SYN has been seen
    int synack_seen;          // SYN-ACK has been seen
    int established;          // handshake finished
} Connection;

// Connection table, defined in connections.c
extern Connection conns[MAX_CONNS];

// Packet counters, defined in stats.c
extern long total_count, total_bytes;
extern long tcp_count, tcp_bytes;
extern long udp_count, udp_bytes;
extern long icmp_count, icmp_bytes;
extern long arp_count, arp_bytes;
extern long ipv6_count, ipv6_bytes;
extern long other_ip_count, other_ip_bytes;
extern long non_ip_count, non_ip_bytes;

// connections.c: find/add a connection entry, -1 for full tbale
int connection_found(const unsigned char *src_ip, const unsigned char *dst_ip, int src_port, int dst_port);

// names.c: readable names for ICMP types and ports
const char *icmp_name(int type);
const char *port_name(int port);

// stats.c: print the packet and byte table
void capture_stats(void);

// decode.c: decode one packet (called by pcap_loop)
void packet_got(u_char *dumper_arg, const struct pcap_pkthdr *header, const u_char *data);

void print_http(const u_char *p, int len);

#endif