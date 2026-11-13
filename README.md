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

## Build and Run

```bash
gcc sniffer.c -o sniffer -lpcap
sudo ./sniffer wlan0
```