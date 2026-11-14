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
10. The transport header position `t` was not dynamic and TCP UDP ICMP was read fixed byte position. 
    - that gave wrong ports icmp types and tcp header lengths
    - `t` is now cacl. as `14 + HLEN*4` for ipv4 (54 for v6) and every port tcp udp and icmp reads it 
11. Saved caputre in `out.pcap`: pcap_dump write every packet, and u can open it in wireshark
    - added fragment offset  and skip ip fragments
12. Counted bytes/portocol 
    - updated `capture_stats()` and added a table like thing to show no. of captures and bytes
    -  TCP UDP ICMP ARP IPv6 other IPv4 and non-IP and the toal
    - each protocols bytes use the full packet length (`header-> length`)
13. Refactored the project into smaller files 
    - Added `notes.md` file, little bit of theory file layout and build steps (AI Generated)
    - `main.c` setup, datalink, filter, dump file and capture loop
    - `decode.c`: `packet_got` decodes each frame
    - `connections.c`: tracks tcp and udp connection
    - `stats.c`: pre protocol counters and capture stats
    - `names.c`: name lookups like icmp and port
    - `sniffer.h`: constants, `connection` struct and shared declarations
14. Added BPF Filter and makefile clean rule, 
    - `sudo ./sniffer <interface> "<bpf filter>"`, for example "tcp port 443"
    - Tested with icmp and arp caputre `icmp` and `arp` and also `tcp port 443` filter
    - icmp: echo req and reply pairs from `ping`
    - arp: req and reply from `ping` the router
15. Added DNS queries and responses from UDP and TCP
    - as it is same port for both tcp and udp which is 53 
    - 12 byte header with 2 byte id and 2 byte flgas and then 4 2bytes cpunts for questions answers auth and addition records
    - www.google.com becomes 3 wwww 6 google 3 com 0
    - the 0 marks the end 
    - after the name 2 btytes for the query type 
    - 1=A, v4 address ; 28 = AAAA, v6 address
    - response 0 and 2, success and server fail 
16. Added HTTP
    - decoded the plain request lines, `host` header and status lines on the poert 80 
    - `http.c` file and `http_print()` 

## Build and Run

```bash
gcc sniffer.c -o sniffer -lpcap
sudo ./sniffer wlan0
```

OR

```
make
sudo ./sniffer <interface>
sudo ./sniffer <interface> "<bpf filter>"
make clean
```