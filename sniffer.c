#include <pcap.h>
#include <stdio.h>

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

    if (pcap_loop(pcap, 0, packet_got, NULL) == -1)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
    }
    pcap_close(pcap);
    return 0;
}