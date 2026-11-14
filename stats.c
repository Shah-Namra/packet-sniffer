#include <stdio.h>
#include "sniffer.h"

// Packet and byte counters, updated by decode.c
long total_count = 0, total_bytes = 0;
long tcp_count = 0, tcp_bytes = 0;
long udp_count = 0, udp_bytes = 0;
long icmp_count = 0, icmp_bytes = 0;
long arp_count = 0, arp_bytes = 0;
long ipv6_count = 0, ipv6_bytes = 0;
long other_ip_count = 0, other_ip_bytes = 0;
long non_ip_count = 0, non_ip_bytes = 0;

// Prints one row per protocol with its packet count and byte count
void capture_stats(void)
{
    printf("\nProtocol      Packets        Bytes\n");
    printf("TCP        %10ld %12ld\n", tcp_count, tcp_bytes);
    printf("UDP        %10ld %12ld\n", udp_count, udp_bytes);
    printf("ICMP       %10ld %12ld\n", icmp_count, icmp_bytes);
    printf("ARP        %10ld %12ld\n", arp_count, arp_bytes);
    printf("IPv6       %10ld %12ld\n", ipv6_count, ipv6_bytes);
    printf("Other IPv4 %10ld %12ld\n", other_ip_count, other_ip_bytes);
    printf("Non-IP     %10ld %12ld\n", non_ip_count, non_ip_bytes);
    printf("Total      %10ld %12ld\n", total_count, total_bytes);
}