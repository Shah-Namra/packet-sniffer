#include <stdio.h>
#include "sniffer.h"

int main(int argc, char *argv[])
{
    char err[PCAP_ERRBUF_SIZE];

    // Which interface you want to capture packets on
    if (argc < 2)
    {
        printf("Usage: sudo ./sniffer <interface>\n");
        return 1;
    }

    // Open the interface: 65535 = max bytes per packet, 1 = promiscuous mode,
    // 1000 = read timeout in milliseconds
    pcap_t *pcap = pcap_open_live(argv[1], 65535, 1, 1000, err);
    if (pcap == NULL)
    {
        printf(" Some error: %s\n", err);
        return 1;
    }

    // The decoder reads Ethernet offsets, so only Ethernet interfaces work
    if (pcap_datalink(pcap) != DLT_EN10MB)
    {
        printf(" Not an Ethernet interface\n");
        return 1;
    }

    // Output saved in out.pcap so you can see it in wireshark
    pcap_dumper_t *dumper = pcap_dump_open(pcap, "out.pcap");
    if (dumper == NULL)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }
    // captures 25 packets, if 0 it will capture till CTRL + C
    if (pcap_loop(pcap, 25, packet_got, (u_char *)dumper) == -1)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
    }

    // Close out.pcap, print the table, close the interface
    pcap_dump_close(dumper);
    capture_stats();
    pcap_close(pcap);
    return 0;
}