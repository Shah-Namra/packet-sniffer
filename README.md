# Packer SNiffer

### C Program that captures live network packets using libpcap.

`pcap_t`: handle type like `int`
- object that represents an open connection to network interface

`pcap_loop`: runs the capture. 
- keeps reading packets from the interface adn calls `packeta_got` function once for each interface



## Commit Log

1. added readme file 
2. added gitignore file
3. Added starter sniffer
    - `sniffer.c` : opens network interface and prints the size fo each packet it captures.
4. Printed SRC Mac, DST Mac and timestamp, ethernet type, and captured size
5. Printed TCP UDP Ports with IPs
    - also added IPv4 related information like flafs fragment offset ttle checksum and all
    - From HLEN we get to know from where tcp/udp jeader is starting
6. Added Port no. 
    - `port_name()`: shows the common ports to names
    - Ukown ports only prints the number
7. Added summary and Stats
    - ipv6 ips, arp request and reply details
    - `capture_stats()`
    - re arranged  `packet_got`
8. Added ICMP protocol Handling, and updated TCP information
    - added `unasgined int` for large values 
    - Flags come from 12th byte of tcp header, each bit signifies omething like SYN, ACK, PSH etc
9. Added Connection Tracking and packet decoding improved
    - `find_connection()` stores each connection and labels its state
    - ports and UDP fields use t, which handles IPv4 options and IPv6
10. 
    - the transport header position `t` was not dynamic and TCP UDP ICMP was read fixed byte position. 
that gave wrong ports icmp types and tcp header lengths
    - t is now cacl. as `14 + HLEN*4` for ipv4 (54 for v6) and every port tcp udp and icmp reads it 
11. Saved caputre in `out.pcap`: pcap_dump write every packet, and u can open it in wireshark
    - added fragment offset  and skip ip fragments

## Build and Run

```bash
gcc sniffer.c -o sniffer -lpcap
sudo ./sniffer wlan0
```