#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string.h>  // for memset
#include <string>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>  // for inet_ntoa
#include <regex>
#include <iostream>
#include "flow.hpp"
#include "flows_handler.hpp"
#include "zlib.h"
#include "reporter.hpp"
#include "url_mapper.hpp"


class Packet_Parser {
    private:
        // Eth variables
        const struct pcap_pkthdr *header;
        const u_char *buffer;
        unsigned short packet_len;
        unsigned short eth_header_len;

        // IP variables
        struct iphdr *ip_header;
        unsigned short ip_header_len;
        unsigned short ip_payload_len;
        unsigned short ip_total_len;
        std::string source_ip;
        std::string dest_ip;

        // TCP variables
        struct tcphdr *tcp_header;
        unsigned short tcp_header_len;
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int ack_number;

        // L7 variables
        unsigned short l7_buffer_len;
        std::string http_text_fragment;
        unsigned short http_payload_len;  // Total payload length including all fragments
        bool gzip_compressed;
        std::string url_base, url_endpoint, url;

        // Helper functions
        void Parse_IP();
        void Parse_TCP();
        void Parse_HTTP();
        std::string Decompress_String(const std::string&);
        bool HTTP_Payload_Exists();

        Flows_Handler flows_handler;
        Reporter reporter;
        URL_Mapper url_mapper;

    public:
        Packet_Parser();
        void Process_Packet(u_char*, const struct pcap_pkthdr*, const u_char*);
};

#endif
