#include "flow.hpp"


Flow::Flow() {
    source_ip = "";
    dest_ip = "";
    source_port = 0;
    dest_port = 0;
    ack_number = 0;
    http_payload_len = 0;
    fragment_remaining_bytes = 0;
    reassembly_complete = false;
    payload = "";
    gzip_compressed = false;
}


void Flow::Set_IPs(std::string source_ip, std::string dest_ip) {
    this->source_ip = source_ip;
    this->dest_ip = dest_ip;
}


void Flow::Set_Ports(unsigned int source_port, unsigned int dest_port) {
    this->source_port = source_port;
    this->dest_port = dest_port;
}


void Flow::Set_Ack_Num(unsigned int ack_number) {
    this->ack_number = ack_number;
}


void Flow::Set_Payload_Len(unsigned int http_payload_len) {
    this->http_payload_len = http_payload_len;
    this->fragment_remaining_bytes = http_payload_len;
}


bool Flow::Reassembly_Done() {
    return reassembly_complete;
}


bool Flow::Flow_Match(std::string source_ip, std::string dest_ip,
                unsigned int source_port, unsigned int dest_port,
                unsigned int ack_number) {
    if (
        this->source_ip == source_ip &&
        this->dest_ip == dest_ip &&
        this->source_port == source_port &&
        this->dest_port == dest_port &&
        this->ack_number == ack_number
    )
        return true;
    else
        return false;
}


void Flow::Payload_Append(std::string payload) {
    this->payload += payload;
    this->fragment_remaining_bytes -= payload.length();

    if (this->fragment_remaining_bytes == 0) {
        reassembly_complete = true;
    }
}


std::string Flow::Get_Payload()
{
    return this->payload;
}


void Flow::Set_Compression(bool compressed)
{
    this->gzip_compressed = compressed;
}


bool Flow::Is_GZip_Compressed()
{
    return this->gzip_compressed;
}
