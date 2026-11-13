cat > PACKET_GUIDE.md << 'EOF'
# Packet Guide

This guide explains the packet headers the sniffer reads and the byte positions the code uses. Read it from top to bottom.

## 1. What a packet looks like

A packet is headers wrapped around data, like envelopes inside envelopes:

~~~
[ Ethernet | IP | TCP or UDP or ICMP | data ]
~~~

Each header tells the code how to read the next one. The code reads the outer header first, then uses its fields to choose the next step.

## 2. Ethernet header (first 14 bytes)

| Bytes | Name | Meaning |
|---|---|---|
| 0-5 | Destination MAC | Hardware address the packet is sent to |
| 6-11 | Source MAC | Hardware address the packet came from |
| 12-13 | EtherType | What is inside: `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP |

## 3. IPv4 header (starts at byte 14, usually 20 bytes)

| Byte | Name | Meaning |
|---|---|---|
| 14 | Version and length | Top 4 bits are the version (4). Bottom 4 bits are the header length in 4-byte units |
| 23 | Protocol | What is inside: `1` ICMP, `6` TCP, `17` UDP |
| 26-29 | Source IP | Sender's address |
| 30-33 | Destination IP | Receiver's address |

The header is 20 bytes when there are no options. The transport header (TCP, UDP, or ICMP) starts right after it. The code calculates that position as `t = 14 + (length × 4)`.

## 4. IPv6 header (always 40 bytes, starts at byte 14)

| Byte | Name | Meaning |
|---|---|---|
| 20 | Next header | Same job as IPv4 protocol: `6` TCP, `17` UDP |
| 21 | Hop limit | How many more hops the packet can make |
| 22-37 | Source IP | 16 bytes |
| 38-53 | Destination IP | 16 bytes |

Since IPv6 headers are always 40 bytes, the transport header always starts at byte 54.

## 5. ARP packet (starts at byte 14)

ARP asks "who has this IP?" and the owner replies with its MAC address.

| Byte | Name | Meaning |
|---|---|---|
| 20-21 | Operation | `1` request, `2` reply |
| 22-27 | Sender MAC | Who is asking or answering |
| 28-31 | Sender IP | Their IP |
| 32-37 | Target MAC | Filled in only in replies |
| 38-41 | Target IP | The IP being asked about |

## 6. TCP header (starts at `t`)

Each offset is counted from the start of the TCP header.

| Offset | Name | Meaning |
|---|---|---|
| 0-1 | Source port | Sender's port |
| 2-3 | Destination port | Receiver's port |
| 4-7 | Sequence number | Position of this data in the stream |
| 8-11 | Ack number | The next byte the sender expects to receive |
| 12 | Header length | Top 4 bits, in 4-byte units |
| 13 | Flags | One bit per flag (see below) |
| 14-15 | Window | How much data the sender can accept |

**Flags (byte 13):**

| Flag | Value | Meaning |
|---|---|---|
| FIN | `0x01` | Sender is finished |
| SYN | `0x02` | Start a connection |
| RST | `0x04` | Reset (abort) the connection |
| PSH | `0x08` | Deliver data now |
| ACK | `0x10` | The ack number is valid |
| URG | `0x20` | The urgent pointer is valid |

Flags combine. `0x12` is SYN plus ACK. `0x18` is PSH plus ACK.

## 7. UDP header (8 bytes, starts at `t`)

| Offset | Name | Meaning |
|---|---|---|
| 0-1 | Source port | Sender's port |
| 2-3 | Destination port | Receiver's port |
| 4-5 | Length | Size of the UDP header and data |
| 6-7 | Checksum | Error check |

UDP has no sequence numbers, flags, or connection setup, which makes it simpler than TCP.

## 8. ICMP header (starts at `t`)

| Offset | Name | Meaning |
|---|---|---|
| 0 | Type | What kind of message (8 = Echo Request, 0 = Echo Reply) |
| 1 | Code | More detail about the type |

ICMP has no ports. `ping` sends Echo Requests and gets Echo Replies.

## 9. What `packet_got` does, step by step

1. Skip the packet if it is shorter than the Ethernet header (14 bytes).
2. Print the MAC addresses, EtherType, and timestamp.
3. Look at the EtherType:
   - IPv4: print the IPs, read the protocol, and set `t`.
   - IPv6: print the IPs and hop limit, read the next header, and set `t = 54`.
   - ARP: print the sender and target, then stop.
   - Anything else: count it as non-IP and stop.
4. Look at the protocol:
   - TCP: count it and print the protocol.
   - UDP: count it and print the protocol.
   - ICMP: print the type and code, then stop (no ports).
   - Anything else: count it as other and stop.
5. Print the ports at `t` and `t + 2`.
6. For TCP, print the sequence, ack, flags, and window, then work out the connection state.
7. For UDP, print the length and checksum.

## 10. Connection tracking

A TCP connection is identified by four values: source IP, source port, destination IP, and destination port. The code keeps a table of these, and labels each packet:

- `NEW (SYN)`: the client starts a connection.
- `SYN-ACK`: the server agrees.
- `ESTABLISHED`: the handshake is finished.
- `DATA`: the connection is open and sending data.
- `CLOSING` or `RESET`: the connection is ending.

This is a simple guess from the flags. Tools like Wireshark track more states.

## 11. Key terms

- **Port**: a number that identifies a service on a machine. 443 is HTTPS, 53 is DNS.
- **Protocol**: the number that says what is inside the IP packet.
- **`t`**: the byte position where the transport header starts. It is 34 for a typical IPv4 packet and 54 for IPv6.
- **Big-endian**: network byte order. The first byte is the most significant, so `(data[t] << 8) | data[t+1]` builds the port number.

## 12. Reading the output

Run the sniffer while you browse or ping. Each packet prints in order:

1. Sizes and timestamp
2. MAC addresses and EtherType
3. IP addresses and protocol
4. Ports, with names where known
5. TCP details or UDP details, or ICMP type

Example: a line `DST PORT: 443 (HTTPS)` means the packet is headed to a secure web server.
EOF