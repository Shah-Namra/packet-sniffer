cat > PACKET_GUIDE.md << 'EOF'
# Packet Guide: Project Structure, How It Works, and the IP Header

This guide explains how the mini packet sniffer is organized, how a packet moves through the program, and the networking theory behind the IPv4 header that the sniffer reads.

---

## 1. What the Program Does

The sniffer listens on a network interface, such as `wlan0` or `eth0`, and captures every frame it can see. For each frame it:

1. Works out the protocol stack: Ethernet, then IPv4, IPv6, or ARP, then TCP, UDP, or ICMP.
2. Prints a short summary of the important header fields.
3. Tracks TCP and UDP conversations as connections.
4. Counts packets and bytes per protocol.
5. Saves every captured frame to `out.pcap`, which Wireshark can open for comparison.

It uses **libpcap**, the same capture library that Wireshark and tcpdump use. libpcap gives the program raw frames. The program's own code decodes them.

---

## 2. Project Structure
```
packet-sniffer/
├── main.c Entry point: open interface, set filter, run capture, print stats
├── decode.c packet_got(): called for every captured frame, decodes the headers
├── connections.c connection_found(): tracks TCP and UDP conversations
├── stats.c Per-protocol counters and capture_stats() table
├── names.c icmp_name() and port_name(): turn numbers into readable names
├── sniffer.h Constants, the Connection struct, and shared declarations
├── Makefile Builds the program with gcc and links libpcap
├── PACKET_GUIDE.md This guide
└── README.md Build, run, and project summary
```


### What each file is responsible for

| File | Responsibility | Why it is separate |
|------|----------------|--------------------|
| `main.c` | Setup and control: interface, datalink check, filter, dump file, capture loop | Keeps setup apart from decoding |
| `decode.c` | Reads the Ethernet, IP, and transport headers and prints them | The core logic; it is the only file that reads raw bytes |
| `connections.c` | Remembers conversations and their handshake state | State is kept in one place |
| `stats.c` | Holds the counters and prints the table | Counting is separate from decoding |
| `names.c` | Lookup tables for ICMP types and well-known ports | Pure data, no logic |
| `sniffer.h` | `MAX_CONNS`, the `Connection` struct, `extern` declarations | Every file includes the same declarations |

Each `.c` file is compiled on its own, then linked into one program. The header file tells the compiler what each function looks like, so the files can call each other.

---

## 3. How the Program Runs

### Step by step

1. **`main.c` opens the interface** with `pcap_open_live()`. The device is put in promiscuous mode so it sees all frames on the link, not only the ones addressed to this machine.
2. **Check the link type.** `pcap_datalink()` must return `DLT_EN10MB`, which means Ethernet. If it does not, the program prints an error and exits. The decoder assumes an Ethernet header is present.
3. **Optional filter.** If a BPF filter such as `"tcp port 443"` is given, `pcap_compile()` and `pcap_setfilter()` tell libpcap to drop everything else in the kernel, before the program sees it.
4. **Open the dump file.** `pcap_dump_open()` creates `out.pcap`. Its handle is passed to the callback as the user argument.
5. **Run the capture loop.** `pcap_loop()` waits for frames and calls `packet_got()` once for each one, until the count is reached.
6. **`packet_got()` in `decode.c` handles one frame:**
   - Increase the total counter and save the frame with `pcap_dump()`.
   - Read the Ethernet type field to choose IPv4, IPv6, ARP, or other.
   - For IPv4: read the header length, the protocol field, and the fragment offset.
   - If the packet is a first fragment or not fragmented, read the transport ports, or the ICMP type.
   - For TCP and UDP: call `connection_found()`, then update the handshake flags.
   - Update the counters in `stats.c`.
7. **Clean up.** `pcap_dump_close()`, `pcap_close()`, then `capture_stats()` prints the protocol table.

### Flow diagram
```
main.c
pcap_open_live ──► pcap_datalink (must be Ethernet)
│
▼
pcap_compile / pcap_setfilter (optional BPF filter)
│
▼
pcap_dump_open(“out.pcap”)
│
▼
pcap_loop(count, packet_got, dumper)
│
▼ one call per frame
decode.c packet_got()
├── total counter++, pcap_dump()
├── Ethernet type ──► IPv4 ──► HLEN, protocol, fragment offset
│ ├── TCP / UDP ──► connections.c connection_found()
│ └── ICMP ──► names.c icmp_name()
├── IPv6 ──► counter
├── ARP ──► counter
└── other ──► counter
│
▼
stats.c capture_stats() prints the table
```


### Why the loop count is 25

`pcap_loop()` takes a count. The program captures 25 packets and then stops, so the output is short and repeatable. The count is a value in `main.c`, so it is easy to change later.

---

## 4. Theory: Layers and Encapsulation

A network message is split into layers, and each layer adds its own header in front of the data from the layer above. This is **encapsulation**.
```
+-----------------+----------------+-----------------------+-----+
| Ethernet header | IPv4 header | TCP or UDP header | data|
+-----------------+----------------+-----------------------+-----+
Layer 2 Layer 3 Layer 4 payload
(frame) (packet) (segment or datagram)
```


Decoding is the reverse: the sniffer reads the outermost header first, uses one of its fields to find the next header, and continues inward.

- The **Ethernet header** says what comes next through its **EtherType** field: `0x0800` for IPv4, `0x86DD` for IPv6, `0x0806` for ARP.
- The **IPv4 header** says what comes next through its **Protocol** field: `1` for ICMP, `6` for TCP, `17` for UDP.
- The **transport header** (TCP or UDP) has the ports, which identify the applications at each end.

---

## 5. The IPv4 Header

The IPv4 header is the part of an IP packet that routers read to deliver it. The minimum size is 20 bytes. Each row below is 32 bits (4 bytes) wide.
```
0 1 2 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Version| HELN | Type of Service / DSCP | Total Length |
+-------+-------+---------------+-------------------------------+
| Identification |Flags| Fragment Offset |
+---------------+---------------+-------------------------------+
| Time to Live | Protocol | Header Checksum |
+---------------+---------------+-------------------------------+
| Source Address |
+---------------------------------------------------------------+
| Destination Address |
+---------------------------------------------------------------+
| Options (optional, rare) |
+---------------------------------------------------------------+
```


### What each field means

| Field | Size | Meaning | Used by the sniffer? |
|-------|------|---------|----------------------|
| **Version** | 4 bits | `4` for IPv4. It tells the reader how to parse the rest. | Only to confirm IPv4 |
| **HLEN** (Internet Header Length) | 4 bits | Header length in 32-bit words. Minimum `5` (20 bytes). Options make it bigger. | Yes. It tells the sniffer where the transport header starts. |
| **Type of Service / DSCP** | 8 bits | Priority hint for quality of service. | No |
| **Total Length** | 16 bits | Size of the whole packet in bytes, header plus data. Maximum 65535. | Shown in the output |
| **Identification** | 16 bits | Same value on every fragment of one original packet. | No |
| **Flags** | 3 bits | Bit 1: Don't Fragment (DF). Bit 2: More Fragments (MF). | Yes, to detect fragments |
| **Fragment Offset** | 13 bits | Where this fragment's data starts, in units of 8 bytes. | Yes. A non-zero value means this is not the first fragment. |
| **Time to Live (TTL)** | 8 bits | Each router lowers it by 1. At 0 the packet is dropped. This stops packets looping forever. | Shown in the output |
| **Protocol** | 8 bits | What is inside: 1 ICMP, 6 TCP, 17 UDP. | Yes, it chooses the next decoder |
| **Header Checksum** | 16 bits | Checks the header only. Each router recalculates it because TTL changes. | No |
| **Source Address** | 32 bits | Sender's IP address. | Yes |
| **Destination Address** | 32 bits | Receiver's IP address. | Yes |
| **Options** | 0 to 40 bytes | Rarely used features such as record route. | Skipped, using HLEN |

### Why the HLEN field matters

The header is not always 20 bytes. If options are present, the header is longer. It tells the reader exactly where the header stops and the TCP or UDP header begins. This is why `decode.c` multiplies HLEN by 4 instead of assuming 20 bytes.

### Fragmentation in theory

Each network link has an **MTU** (Maximum Transmission Unit). Ethernet's MTU is 1500 bytes. A router that receives a bigger packet splits it into fragments. Each fragment has:

- the same **Identification** value,
- its own **Fragment Offset**,
- **MF** set to 1, except on the last fragment.

Only the final destination puts the fragments back together. Fragments after the first one do not contain the TCP or UDP header, so the sniffer does not read ports from them. It prints a note instead.

---

## 6. The Transport Headers the Sniffer Reads

### TCP (connection-oriented, reliable)

TCP keeps a conversation in order and recovers lost data. Its header includes:

- **Source and destination port**: which application on each side.
- **Sequence and acknowledgement numbers**: count the bytes, so data can be put in order.
- **Flags**: SYN (start a connection), ACK (acknowledge), FIN (finish), RST (reset), PSH (push data now), URG (urgent).

A normal connection starts with a **three-way handshake**:
```
Client ──SYN──────────► Server
Client ◄──SYN, ACK───── Server
Client ──ACK──────────► Server connection established
```


### UDP (connectionless, unreliable)

UDP has no handshake, no ordering, and no retransmission. Its header has only four fields: source port, destination port, length, and checksum. It is used when speed matters more than guaranteed delivery, such as DNS, DHCP, and video.

### ICMP (control messages)

ICMP has no ports. Its header starts with a **type** and a **code**. For example, type 8 is an echo request (ping), type 0 is an echo reply, and type 11 is time exceeded (used by traceroute). `names.c` turns the type into a name.

---

## 7. Connection Tracking (`connections.c`)

A TCP or UDP conversation is identified by two endpoints: the source IP and port, and the destination IP and port.

The problem: a packet from A to B and the reply from B to A have the endpoints swapped. A simple lookup would treat them as two different connections.

The solution is to **sort the two endpoints** before storing them. The lower one is stored as `lo`, the higher as `hi`. Both directions then produce the same key and land in the same table slot.

`connection_found()` does this:

1. Sort the endpoints into `lo` and `hi`.
2. Search the table of `MAX_CONNS` (100) slots for a match.
3. If found, return its index. If not found, store it in an empty slot and return the new index. If the table is full, return -1.

Each `Connection` entry also records flags, such as whether a SYN was seen, whether a SYN-ACK was seen, and whether the connection is established. This gives a simple view of the handshake. Data packets after the handshake do not change these flags, so the state can look empty for them. That is expected.

---

## 8. Counting (`stats.c`)

`stats.c` keeps a counter for each category: total, TCP, UDP, ICMP, ARP, IPv6, other IP, and non-IP. Each counter stores packets and bytes. `capture_stats()` prints them as a table at the end of the run.

Comparing these numbers with Wireshark's Protocol Hierarchy view is a good check for the report.

---

## 9. Build and Run

```bash
make
sudo ./sniffer wlan0
sudo ./sniffer wlan0 "tcp port 443"   # optional BPF filter
```

- `sudo` is needed because raw capture requires privileges.
- The Makefile uses `-Wall -Wextra -g` and links with `-lpcap`.
- Open `out.pcap` in Wireshark to compare the captured frames with the printed output.

---

## 10. Limits and Responsible Use

- The program captures 25 packets by default and does not yet decode DNS or HTTP.
- It only reads the first fragment's transport header.
- It tracks connection state for handshakes only. It does not reassemble streams.
- Capture only on networks you own or have permission to monitor. Captured traffic can contain private data.
