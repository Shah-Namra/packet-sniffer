#include <stdio.h>
#include "sniffer.h"

int main(int argc, char *argv[])
{
    char err[PCAP_ERRBUF_SIZE];

    // Which interface you want to capture packets on
    if (argc < 2)
    {
        printf("Usage: sudo ./sniffer <interface> [bpf filter]\n");
        return 1;
    }

    // Open the interface: 65535 = max bytes per packet, 1 = promiscuous mode,
    // 1000 = read timeout in milliseconds
    pcap_t *pcap = pcap_open_live(argv[1], 65535, 1, 1000, err);
    if (pcap == NULL)
    {
        printf("Some error: %s\n", err);
        return 1;
    }

    // The decoder reads Ethernet offsets, so only Ethernet interfaces work
    if (pcap_datalink(pcap) != DLT_EN10MB)
    {
        printf("Not an Ethernet interface\n");
        pcap_close(pcap);
        return 1;
    }

    // Optional filter "tcp port 443" after sudo ./filename "tcp port 443"
    if (argc == 3)
    {
        struct bpf_program fp;

        // pcap_compile checks the filter text.. pcap_geterr explains a typo
        if (pcap_compile(pcap, &fp, argv[2], 1, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "Bad filter '%s': %s\n", argv[2], pcap_geterr(pcap));
            pcap_close(pcap);
            return 1;
        }

        if (pcap_setfilter(pcap, &fp) == -1)
        {
            fprintf(stderr, "Could not set filter: %s\n", pcap_geterr(pcap));
            pcap_freecode(&fp);
            pcap_close(pcap);
            return 1;
        }

        pcap_freecode(&fp);
    }

    // Output saved in out.pcap so you can see it in Wireshark
    pcap_dumper_t *dumper = pcap_dump_open(pcap, "out.pcap");
    if (dumper == NULL)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }

    // Captures 25 packets
    if (pcap_loop(pcap, 10, packet_got, (u_char *)dumper) == -1)
    {
        printf("Error: %s\n", pcap_geterr(pcap));
    }

    // Close out.pcap, print the table, close the interface
    pcap_dump_close(dumper);
    capture_stats();
    pcap_close(pcap);
    return 0;
}