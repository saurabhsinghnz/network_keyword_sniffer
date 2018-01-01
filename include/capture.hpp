#ifndef CAPTURE_H
#define CAPTURE_H

#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "packet_parser.hpp"


class Capture {
    private:
        pcap_if_t *alldevsp, *device;
        pcap_t *handle;  // Handle of the device being sniffed
        char errbuf[100], *devname;
        
        void Get_Capture_Device();
        void Open_Capture_Device();
        int Set_Capture_Filter(char *);
        static void Process_Packet(u_char*, const struct pcap_pkthdr*, const u_char*);

    public:
        static Packet_Parser *pkt_parser;
        Capture();
        int Start(char *);
};

#endif
