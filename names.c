#include "sniffer.h"

// Returns the name of an ICMP type number (for example 8 = Echo Request)
const char *icmp_name(int type)
{
    switch (type)
    {
    case 0:
        return "Echo Reply";
    case 3:
        return "Destination Unreachable";
    case 4:
        return "Source Quench";
    case 5:
        return "Redirect";
    case 8:
        return "Echo Request";
    case 11:
        return "Time Exceeded";
    case 12:
        return "Parameter Problem";
    case 13:
        return "Timestamp Request";
    case 14:
        return "Timestamp Reply";
    case 15:
        return "Information Request";
    case 16:
        return "Information Reply";
    default:
        return "Unknown ICMP Type";
    }
}

// Returns the name of a port number 
const char *port_name(int port)
{
    switch (port)
    {
    case 20:
        return "FTP Data";
    case 21:
        return "FTP Control";
    case 22:
        return "SSH";
    case 23:
        return "Telnet";
    case 25:
        return "SMTP";
    case 53:
        return "DNS";
    case 67:
        return "DHCP Server";
    case 68:
        return "DHCP Client";
    case 80:
        return "HTTP";
    case 110:
        return "POP3";
    case 143:
        return "IMAP";
    case 443:
        return "HTTPS";
    default:
        return "Unknown";
    }
}