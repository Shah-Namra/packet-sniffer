#include <stdio.h>
#include "sniffer.h"
#include <string.h>
// Prints the DNS header and the first question name.
// dns points to the first byte of the DNS message; len is how many bytes are left.
static void print_dns(const u_char *dns, int len)
{
    if (len < 12)
    {
        printf(" DNS: message too short\n");
        return;
    }

    unsigned id = (dns[0] << 8) | dns[1];
    unsigned flags = (dns[2] << 8) | dns[3];
    int is_response = (flags >> 15) & 1; // 1 = response, 0 = query
    int rcode = flags & 0x0F;            // response code: 0 = OK
    unsigned qcount = (dns[4] << 8) | dns[5];

    printf(" DNS ID: 0x%04x\n", id);
    printf(" DNS Type: %s\n", is_response ? "Response" : "Query");
    printf(" DNS Questions: %u\n", qcount);

    if (qcount == 0)
        return;

    // Read the first question name: labels, ending with a zero byte
    char name[256] = "";
    size_t n = 0;
    int pos = 12;

    while (pos < len && dns[pos] != 0)
    {
        int label = dns[pos];
        if (label & 0xC0 || pos + 1 + label > len || n + label + 1 >= sizeof(name))
            break; // compressed or broken name: stop
        if (n > 0)
            name[n++] = '.';
        memcpy(name + n, dns + pos + 1, label);
        n += label;
        pos += label + 1;
    }

    name[n] = '\0';
    printf(" DNS Query Name: %s\n", name);

    if (pos + 2 < len)
    {
        unsigned qtype = (dns[pos + 1] << 8) | dns[pos + 2];
        printf(" DNS Query Type: %u\n", qtype);
    }

    if (is_response)
        printf(" DNS Response Code: %d\n", rcode);
}

// Called by pcap_loop once for every captured packet.
// dumper_arg is the out.pcap file handle, passed in from main.
void packet_got(u_char *dumper_arg, const struct pcap_pkthdr *header, const u_char *data)
{
    // saving the raw packert in out.pcap
    pcap_dump(dumper_arg, header, data);

    // every packet is counted with total size
    total_count++;
    total_bytes += header->len;

    // Number of bytes actually captured (may be smaller than header->len)
    int len = (int)header->caplen;

    // An Ethernet header is 14 bytes so less than that dont make sense
    if (len < 14)
    {
        return;
    }

    // Ethernet Header Details
    printf("\n Packet size: %u bytes\n", header->len);
    printf("Captured size: %u bytes\n", header->caplen);
    printf(" Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
    printf(" SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[6], data[7], data[8], data[9], data[10], data[11]);
    printf(" Ethertype: 0x%02x%02x\n", data[12], data[13]);
    printf(" Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);

    int ether_type = (data[12] << 8) | data[13];
    int protocol = -1; // 6 = TCP, 17 = UDP, 1 = ICMP, anything else = other
    int t = 0;         // byte position where the TCP/UDP/ICMP header starts

    // IPv4 (EtherType 0x0800)
    if (ether_type == 0x0800)
    {
        if (len < 34)
        {
            printf(" Not a complete IPv4 header\n");
            return;
        }

        // HLEN 4 bit field, multiply 4 to get the ipv4 header size, and after that Transport layer starts
        // 0x0F = 15
        protocol = data[23];
        t = 14 + (data[14] & 0x0F) * 4;

        printf(" SRC IP: %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
        printf(" DST IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);

        // only first fragment of the ip packet carries transport header, which hold port no.
        // fragements after that dont contain
        // so this checks fragment offset if its not 0 it prints a note and skips port parsing
        int frag_offset = ((data[20] & 0x1F) << 8) | data[21];
        if (frag_offset != 0)
        {
            printf(" IP Fragmented packet, offset: %d\n", frag_offset);
            return;
        }
    }
    // IPv6 (EtherType 0x86DD): the header is always 40 bytes or more
    else if (ether_type == 0x86DD)
    {
        ipv6_count++;
        ipv6_bytes += header->len;

        if (len < 54)
        {
            printf(" Not a complete IPv6 header\n");
            return;
        }

        protocol = data[20]; // "next header" field
        t = 54;              // transport kayer header start after the 40byte v6 header

        printf("SRC IPv6: ");
        for (int i = 0; i < 16; i += 2)
        {
            printf("%02x%02x", data[22 + i], data[23 + i]);
            if (i < 14)
                printf(":");
        }
        printf("\n");

        printf("DST IPv6: ");
        for (int i = 0; i < 16; i += 2)
        {
            printf("%02x%02x", data[38 + i], data[39 + i]);
            if (i < 14)
                printf(":");
        }
        printf("\n");

        printf("Hop limit: %d\n", data[21]);
    }
    // ARP (EtherType 0x0806)
    else if (ether_type == 0x0806)
    {
        arp_count++;
        arp_bytes += header->len;

        printf(" ARP Packet\n");

        if (len < 42)
        {
            printf(" Not a complete ARP header\n");
            return;
        }
        // ARP operation: 1 = request ("who has"), 2 = reply ("is at")
        int arp_op = (data[20] << 8) | data[21];
        printf(" ARP Operation: %s\n",
               arp_op == 1 ? "Request (who has)" : arp_op == 2 ? "Reply (is at)"
                                                               : "Other");
        // Sender MAC and IP, then target MAC and IP
        printf(" SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[22], data[23], data[24], data[25], data[26], data[27]);
        printf(" SRC IP: %d.%d.%d.%d\n", data[28], data[29], data[30], data[31]);
        printf(" DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[32], data[33], data[34], data[35], data[36], data[37]);
        printf(" DST IP: %d.%d.%d.%d\n", data[38], data[39], data[40], data[41]);

        arp_check(data + 28, data + 22);

        return;
    }
    // Any other EtherType
    else
    {
        non_ip_count++;
        non_ip_bytes += header->len;
        printf(" Not an IPv4 or IPv6 packet\n");
        return;
    }

    // Transport layer: TCP, UDP, or ICMP
    if (protocol == 6)
    {
        tcp_count++;
        tcp_bytes += header->len;
        printf(" Protocol: TCP\n");
    }
    else if (protocol == 17)
    {
        udp_count++;
        udp_bytes += header->len;
        printf(" Protocol: UDP\n");
    }
    else if (protocol == 1)
    {
        icmp_count++;
        icmp_bytes += header->len;
        printf(" Protocol: ICMP\n");

        if (len < t + 2)
        {
            printf(" Not complete ICMP Header\n");
            return;
        }

        int icmp_type = data[t];
        int icmp_code = data[t + 1];
        printf("ICMP Type: %d (%s)\n", icmp_type, icmp_name(icmp_type));
        printf("ICMP Code: %d\n", icmp_code);
        return; // ICMP has no ports
    }
    else
    {
        other_ip_count++;
        other_ip_bytes += header->len;
        printf(" Protocol: Other (%d)\n", protocol);
        return;
    }

    // TCP and UDP both start with src port and dst port
    if (len < t + 4)
    {
        printf(" Not complete TCP/UDP Header\n");
        return;
    }

    int src_port = (data[t] << 8) | data[t + 1];
    int dst_port = (data[t + 2] << 8) | data[t + 3];
    printf(" SRC PORT: %d (%s)\n", src_port, port_name(src_port));
    printf(" DST PORT: %d (%s)\n", dst_port, port_name(dst_port));

    // TCP feilds sqc, ack, flags, window
    if (protocol == 6 && len >= t + 20)
    {
        unsigned int seq = ((unsigned int)data[t + 4] << 24) | ((unsigned int)data[t + 5] << 16) |
                           ((unsigned int)data[t + 6] << 8) | data[t + 7];
        unsigned int ack = ((unsigned int)data[t + 8] << 24) | ((unsigned int)data[t + 9] << 16) |
                           ((unsigned int)data[t + 10] << 8) | data[t + 11];
        int header_len = (data[t + 12] >> 4) * 4; // data offset, in 4 byte words
        unsigned char flags = data[t + 13];
        int window = (data[t + 14] << 8) | data[t + 15];

        printf(" TCP Header Length: %d bytes\n", header_len);
        printf(" Sequence: %u\n", seq);
        printf(" Ack: %u\n", ack);

        printf(" Flags: ");
        if (flags & 0x02)
            printf("SYN ");
        if (flags & 0x10)
            printf("ACK ");
        if (flags & 0x08)
            printf("PSH ");
        if (flags & 0x04)
            printf("RST ");
        if (flags & 0x01)
            printf("FIN ");
        if (flags & 0x20)
            printf("URG ");
        printf("(0x%02x)\n", flags);
        printf(" Window: %d\n", window);

        // Connection tracking uses IPv4 addresses only (4 bytes each)
        int i = (ether_type == 0x0800) ? connection_found(data + 26, data + 30, src_port, dst_port) : -1;

        const char *state = "";
        if (i >= 0)
        {
            Connection *c = &conns[i];

            if (flags & 0x04)
            {
                state = "RESET";
            }
            else if (flags & 0x01)
            {
                state = "CLOSING";
            }
            else if ((flags & 0x02) && !(flags & 0x10))
            {
                c->syn_seen = 1;
                state = "NEW (SYN)";
            }
            else if ((flags & 0x02) && (flags & 0x10))
            {
                c->synack_seen = 1;
                state = "SYN-ACK";
            }
            else if ((flags & 0x10) && c->syn_seen && c->synack_seen && !c->established)
            {
                c->established = 1;
                state = "ESTABLISHED";
            }
            else if (c->established)
            {
                state = "DATA";
            }
        }
        printf(" Connection state: %s\n", state);
        if ((src_port == 80 || dst_port == 80) && len > t + header_len)
        {
            print_http(data + t + header_len, len - (t + header_len));
        }
        if (src_port == 53 || dst_port == 53)
        {
            int dns_start = t + header_len + 2;
            if (dns_start < len)
                print_dns(data + dns_start, len - dns_start);
        }
    }
    // UDP fields length and checksum (8 byte header)
    else if (protocol == 17)
    {
        if (len < t + 8)
        {
            printf(" Not complete UDP Header\n");
            return;
        }
        printf(" UDP Length: %d\n", (data[t + 4] << 8) | data[t + 5]);
        printf(" UDP Checksum: 0x%04x\n", (data[t + 6] << 8) | data[t + 7]);

        //
        if (src_port == 53 || dst_port == 53)
        {
            print_dns(data + t + 8, header->caplen - (t + 8));
        }
    }
};