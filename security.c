#include <stdio.h>
#include <string.h>
#include "sniffer.h"

#define MAX_ARP_ENTRIES 256

typedef struct
{
    int in_use;
    unsigned char ip[4];
    unsigned char mac[6];
} ArpEntry;

static ArpEntry arp_table[MAX_ARP_ENTRIES];

static void print_mac(const unsigned char *m)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Called for every ARP packet with the sender's IP and MAC.
// If an IP seen before now uses a different MAC, print a warning.
void arp_check(const u_char *ip, const u_char *mac)
{
    int free_slot = -1;

    for (int i = 0; i < MAX_ARP_ENTRIES; i++)
    {
        if (!arp_table[i].in_use)
        {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }

        if (memcmp(arp_table[i].ip, ip, 4) == 0)
        {
            if (memcmp(arp_table[i].mac, mac, 6) != 0)
            {
                printf(" WARNING: possible ARP spoofing: %d.%d.%d.%d changed MAC from ",
                       ip[0], ip[1], ip[2], ip[3]);
                print_mac(arp_table[i].mac);
                printf(" to ");
                print_mac(mac);
                printf("\n");
                memcpy(arp_table[i].mac, mac, 6);
            }
            return;
        }
    }

    // First time this IP is seen: remember it
    if (free_slot >= 0)
    {
        arp_table[free_slot].in_use = 1;
        memcpy(arp_table[free_slot].ip, ip, 4);
        memcpy(arp_table[free_slot].mac, mac, 6);
    }
}
