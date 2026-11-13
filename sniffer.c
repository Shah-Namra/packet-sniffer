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
    int ip_header_length = (data[14] & 0x0F) * 4;
    int protocol = data[23];

    printf(" SRC IP: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
    printf(" DST IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);

    //printf(" Version: %d\n", data[14] >> 4);
    //printf(" IP Header Length: %d bytes\n", ip_header_length);
    //printf(" TOS: 0x%02x\n", data[15]);
    //printf(" Total Length: %d\n", (data[16] << 8) | data[17]);
    //printf(" Identification: 0x%02x%02x\n", data[18], data[19]);
    //printf(" Flags: %d\n", (data[20] >> 5) & 0x07);
    //printf(" Fragment Offset: %d\n", ((data[20] & 0x1F) << 8) | data[21]);
    //printf(" TTL: %d\n", data[22]);
    //printf(" Protocol: %d\n", data[23]);
    //printf(" Header Checksum: 0x%02x%02x\n", data[24], data[25]);
    //printf(" SRC IP: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
    //printf(" DST IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);

    // for tcp udp
    //
    int transport_header_offset = 14 + ip_header_length;
    if (protocol == 6)
        printf(" Protocol: TCP\n");
    else if (protocol == 17)
        printf(" Protocol: UDP\n");
    else
    {
        printf(" Protocol: Other (%d)\n", protocol);
        return;
    }

    // 4 bytes for ports
    if (header->caplen < transport_header_offset + 4)
    {
        printf(" Not a complete transport header\n");
        return;
    }

    int src_port = (data[transport_header_offset] << 8) | data[transport_header_offset + 1];
    int dst_port = (data[transport_header_offset + 2] << 8) | data[transport_header_offset + 3];
    printf(" SRC PORT: %d\n", src_port);
    printf(" DST PORT: %d\n", dst_port);
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

    if (pcap_loop(pcap, 1, packet_got, NULL) == -1)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
    }
    pcap_close(pcap);
    return 0;
}