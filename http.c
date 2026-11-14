#include <stdio.h>
#include <string.h>
#include "sniffer.h"

// Prints the first line of a plain HTTP request or response, and the Host header for requests
void print_http(const u_char *p, int len)
{
    const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"};
    int is_request = 0;
    int is_response = 0;

    // request = method + space.. example "GET /"
    for (int i = 0; i < 6; i++)
    {
        int mlen = (int)strlen(methods[i]);
        if (len > mlen && memcmp(p, methods[i], mlen) == 0 && p[mlen] == ' ')
            is_request = 1;
    }

    //  response =  "HTTP/"
    if (len >= 5 && memcmp(p, "HTTP/", 5) == 0)
        is_response = 1;

    // Not HTTP text
    if (!is_request && !is_response)
        return;

    // Print the first line, which ends at \r\n
    int line_len = 0;
    while (line_len < len && line_len < 200 && p[line_len] != '\r' && p[line_len] != '\n')
        line_len++;
    printf(" HTTP: %.*s\n", line_len, (const char *)p);

    // The Host header tells which website this request is for
    if (is_request)
    {
        const char *key = "\nHost: ";
        int klen = (int)strlen(key);
        for (int i = 0; i + klen <= len; i++)
        {
            if (memcmp(p + i, key, klen) == 0)
            {
                int start = i + klen;
                int hlen = 0;
                while (start + hlen < len && hlen < 100 && p[start + hlen] != '\r' && p[start + hlen] != '\n')
                    hlen++;
                printf(" HTTP Host: %.*s\n", hlen, (const char *)(p + start));
                break;
            }
        }
    }
}
