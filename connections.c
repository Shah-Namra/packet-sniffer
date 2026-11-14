#include <string.h>
#include "sniffer.h"

// The connection table, shared with decode.c
Connection conns[MAX_CONNS];

// Finds the table entry for a connection, or adds a new one
// Both directions of a connection give the same entry because the two endpoints are sorted before lookup (lower IP first, then lower port)
// Returns the index in conns[], or -1 if the table is full
int connection_found(const unsigned char *src_ip, const unsigned char *dst_ip, int src_port, int dst_port)
{
    // swap = 1 when the source endpoint is the higher one
    int swap = (memcmp(src_ip, dst_ip, 4) > 0) ||
               (memcmp(src_ip, dst_ip, 4) == 0 && src_port > dst_port);

    // lo = lower endpoint, hi = higher endpoint
    const unsigned char *lo_ip = swap ? dst_ip : src_ip;
    const unsigned char *hi_ip = swap ? src_ip : dst_ip;
    int lo_port = swap ? dst_port : src_port;
    int hi_port = swap ? src_port : dst_port;

    // Looking for an already existing entry
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].in_use &&
            memcmp(conns[i].src_ip, lo_ip, 4) == 0 &&
            memcmp(conns[i].dst_ip, hi_ip, 4) == 0 &&
            conns[i].src_port == lo_port &&
            conns[i].dst_port == hi_port)
        {
            return i;
        }
    }

    // Not found: use the first free slot
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (!conns[i].in_use)
        {
            conns[i].in_use = 1;
            memcpy(conns[i].src_ip, lo_ip, 4);
            memcpy(conns[i].dst_ip, hi_ip, 4);
            conns[i].src_port = lo_port;
            conns[i].dst_port = hi_port;
            conns[i].syn_seen = 0;
            conns[i].synack_seen = 0;
            conns[i].established = 0;
            return i;
        }
    }

    return -1; // table is full
}