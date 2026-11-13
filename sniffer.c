#include <pcap.h>
#include <stdio.h>

void packet_got(u_char *unused, const struct pcap_pkthdr *header, const u_char *data)
{
    printf("Packet size: %u bytes\n", header->len);
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