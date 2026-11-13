cat > README.md << 'EOF'
# Packet Sniffer

A small C program that captures live network packets with libpcap and prints the fields inside each packet's headers.

## Files

| File | What it is |
|---|---|
| `sniffer.c` | The whole program |
| `README.md` | This file: what the project does and how to run it |
| `PACKET_GUIDE.md` | Explains each header and the byte offsets the code reads |
| `.gitignore` | Stops compiled files and installers from going to GitHub |

## Build and Run

~~~bash
gcc -Wall -Wextra sniffer.c -o sniffer -lpcap
sudo ./sniffer wlan0
~~~

- Replace `wlan0` with your interface name (run `ip link` to see them).
- `sudo` is needed because capturing packets is a privileged operation.
- The program captures 25 packets, then prints a summary. Change the number in `pcap_loop` in `main` to capture more.

## What It Decodes

| Layer | What is printed |
|---|---|
| Ethernet | Destination MAC, source MAC, EtherType, timestamp |
| IPv4 | Source IP, destination IP, protocol |
| IPv6 | Source IP, destination IP, hop limit |
| ARP | Sender and target MAC and IP |
| TCP | Ports, sequence, ack, flags, window, connection state |
| UDP | Ports, length, checksum |
| ICMP | Type (such as Echo Request) and code |

## How It Works

1. `main` opens the interface with `pcap_open_live`.
2. `pcap_loop` reads one packet at a time and calls `packet_got` for each.
3. `packet_got` reads the Ethernet header, then looks at the EtherType to find IPv4, IPv6, or ARP.
4. For IPv4 and IPv6, it reads the protocol (TCP, UDP, or ICMP) and finds where the transport header starts.
5. For TCP and UDP, it reads the ports. For TCP, it also reads the flags and tracks the connection.
6. When the loop ends, `capture_stats` prints the counts.

## Functions

| Function | What it does |
|---|---|
| `main` | Checks the command line, opens the interface, runs the capture loop, prints the summary |
| `packet_got` | Decodes one packet. Called by libpcap for every packet |
| `find_connection` | Finds or creates the table entry for a TCP connection |
| `port_name` | Turns a port number into a name, such as 443 into HTTPS |
| `icmp_name` | Turns an ICMP type number into a name, such as 8 into Echo Request |
| `capture_stats` | Prints how many packets of each kind were seen |

## Main libpcap Calls

- **`pcap_t`**: a handle to an open interface. Every libpcap call uses it.
- **`pcap_open_live`**: opens the interface and returns a handle.
- **`pcap_loop`**: captures packets and calls a function for each one.
- **`pcap_close`**: closes the handle.

## Commit Log

1. **Added README file**: first project description.
2. **Added .gitignore**: ignores `sniffer`, `sniffer.exe`, `*.o`, and `*.deb`.
3. **Added starter sniffer**: opens an interface and prints each packet's size.
4. **Printed MAC addresses, EtherType, and timestamp**: reads the 14-byte Ethernet header.
5. **Printed TCP and UDP ports with IP addresses**: reads the IPv4 header length to find the transport header.
6. **Showed names for well-known ports**: `port_name()` maps numbers to names.
7. **Added packet summary**: `capture_stats()` prints counts for each protocol.
8. **Added IPv6, ARP, and TCP fields**: IPv6 addresses, ARP details, sequence, ack, flags, and window.
9. **Updated README**: described the protocols and TCP fields.
10. **Decoded ICMP type and code**: `icmp_name()` gives types readable names.
11. **Fixed TCP fields**: sequence and ack are unsigned, and flags come from byte 13.
12. **Tracked TCP connection state**: `find_connection()` stores each connection and labels its state.
13. **Added PACKET_GUIDE.md**: explains headers and offsets.
14. **Used computed transport offset**: ports and UDP fields use `t`, which handles IPv4 options and IPv6.
EOF