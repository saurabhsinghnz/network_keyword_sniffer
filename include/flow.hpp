#ifndef FLOW_H
#define FLOW_H

#include <string>


class Flow {
    private:
        // Flow identifiers
        std::string source_ip;
        std::string dest_ip;
        unsigned int source_port;
        unsigned int dest_port;
        unsigned int ack_number;

        unsigned int http_payload_len;
        unsigned int fragment_remaining_bytes;
        bool reassembly_complete;
        std::string payload;
        bool gzip_compressed;

    public:
        Flow();

        void Set_IPs(std::string source_ip, std::string dest_ip);
        void Set_Ports(unsigned int source_port, unsigned int dest_port);
        void Set_Ack_Num(unsigned int ack_number);
        void Set_Payload_Len(unsigned int http_payload_len);

        bool Reassembly_Done();

        bool Flow_Match(std::string source_ip, std::string dest_ip,
                        unsigned int source_port, unsigned int dest_port,
                        unsigned int ack_number);

        void Payload_Append(std::string payload);

        std::string Get_Payload();
        void Set_Compression(bool);
        bool Is_GZip_Compressed();
};

#endif
