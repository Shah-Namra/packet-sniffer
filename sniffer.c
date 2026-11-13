#include <pcap.h>
#include <stdio.h>

// ethernet packet:
// 0-5: Destination MAC
// 6-11: Source MAC
// 12-13: Ethertype
// 14 onwards : Payload...

// in payload IP Header, TCP, UDP, and others
// from 14 to 25: Version, HLen, TOS, packet length, identification, flags, fragment offset, TTL, protocol, checksum, SRC IP, DST IP, SRC PORT, DST PORT, Length, UDP checksum, Payload...

// 14: Version, HLEM
// 15: TOS
// 16-17: Packet length
// 18-19: Identification
// 20-21: Flags + Fragment offset
// 22: TTL
// 23: Protocol 6 TCP, 17 UDP
// 24-25: Header checksum
// 26-29: SRC IP
// 30-33: DST IP
// 34 onwards: TCP / UDP

// 34- 35 SRC PORT
// 36- 37 DST PORT

// if UDP
// 38-39 Length
// 40-41 UDP Checksum
// 42 onwards: Payload

static long tcp_count = 0;
static long udp_count = 0;
static long other_ip_count = 0;
static long non_ip_count = 0;
static long ipv6_count = 0;
static long arp_count = 0;

void capture_stats()
{
    printf("\nCapture Statistics:\n");
    printf("TCP Packets: %ld\n", tcp_count);
    printf("UDP Packets: %ld\n", udp_count);
    printf("Other IP Packets: %ld\n", other_ip_count);
    printf("Non-IP Packets: %ld\n", non_ip_count);
    printf("IPv6 Packets: %ld\n", ipv6_count);
    printf("ARP Packets: %ld\n", arp_count);
}

const char *port_name(int port)
{
    switch (port)
    {
    case 20:
        return "FTP Data";
    case 21:
        return "FTP Control";
    case 22:
        return "SSH";
    case 23:
        return "Telnet";
    case 25:
        return "SMTP";
    case 53:
        return "DNS";
    case 67:
        return "DHCP Server";
    case 68:
        return "DHCP Client";
    case 80:
        return "HTTP";
    case 110:
        return "POP3";
    case 143:
        return "IMAP";
    case 443:
        return "HTTPS";
    default:
        return "Unknown";
    }
}

// ipv6 address is 16 bytes long, print it in hex format with colons


void packet_got(u_char *unused, const struct pcap_pkthdr *header, const u_char *data)
{
    if (header->caplen < 14)
    {
        return;
        // too short to contain Ethernet header
    }
    printf("\n Packet size: %u bytes\n", header->len);
    printf("Captured size: %u bytes\n", header->caplen);
    printf(" Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
    printf(" SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[6], data[7], data[8], data[9], data[10], data[11]);
    printf(" Ethertype: 0x%02x%02x\n", data[12], data[13]);
    printf(" Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);

    int ether_type = (data[12] << 8) | data[13];
    int protocol = -1;   // 6 TCP, 17 UDP, anything else = other
    int t = 0;           // where the TCP/UDP header starts
    // now for ipv4, SRC IP and DST IP
    if (data[12] != 0x08 || data[13] != 0x00)
    {
        printf(" Not an IPv4 packet\n");
        return;
    }

    // 20 bytes for ipv4 header after ether header
    if (header->caplen < 34)
    {
        printf(" Not a complete IPv4 header\n");
        return;
    }

    // if ethernet is 0x0800 IPv4
    if (ether_type == 0x0800)
    {
        if (header->caplen < 34)
        {
            printf(" Not a complete IPv4 header\n");
            return;
        }
        int ip_header_length = (data[14] & 0x0F) * 4; // HLEN = 4bits, multiple of 4, 15th bit
        protocol = data[23];

        printf(" SRC IP: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
        printf(" DST IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);
    }

    // for ipv6
    else if (ether_type == 0x86DD)
    {
        ipv6_count++;
        if (header->caplen < 54)
        {
            printf(" Not a complete IPv6 header\n");
            return;
        }
        protocol = data[20];

        printf(" SRC IPv6: ");
        for (int i = 0; i < 16; i += 2)
        {
            printf("%02x%02x", data[22 + i], data[23 + i]);
            if (i < 14)
                printf(":");
        }

        printf("\n");

        printf(" DST IPv6: ");
        for (int i = 0; i < 16; i += 2)
        {
            printf("%02x%02x", data[38 + i], data[39 + i]);
            if (i < 14)
                printf(":");
        }
        printf("\n");

    }
    // ARP Packet
    else if(ether_type == 0x0806)
    {
        arp_count++;
        printf(" ARP Packet\n");
        if(header ->caplen < 42)
        {
            printf(" Not a complete ARP header\n");
            return;
        }
        printf(" SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[22], data[23], data[24], data[25], data[26], data[27]);
        printf(" SRC IP: %d.%d.%d.%d\n", data[28], data[29], data[30], data[31]);
        printf(" DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[32], data[33], data[34], data[35], data[36], data[37]);
        printf(" DST IP: %d.%d.%d.%d\n", data[38], data[39], data[40], data[41]);

        return;
    }
    // Something else
    else
    {
        printf(" Not an IPv4 or IPv6 packet\n");
        non_ip_count++;
        return;
    }

    if(protocol == 6)
    {
        tcp_count++;
        printf(" Protocol: TCP\n");
    }
    else if(protocol == 17)
    {
        udp_count++;
        printf(" Protocol: UDP\n");
    }
    else
    {
        other_ip_count++;
        printf(" Protocol: Other (%d)\n", protocol);
        return;
    }


    
}

int main(int argc, char *argv[])
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 2)
    {
        printf("Usage: sudo ./sniffer <interface>\n");
        return 1;
    }

    pcap_t *pcap = pcap_open_live(argv[1], 65535, 1, 1000, err);
    if (pcap == NULL)
    {
        printf(" Some error: %s\n", err);
        return 1;
    }

    if (pcap_loop(pcap, 25, packet_got, NULL) == -1)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
    }
    capture_stats();
    pcap_close(pcap);
    return 0;
}