#include "packet_parser.hpp"


Packet_Parser::Packet_Parser()
{
    eth_header_len = sizeof(struct ethhdr);
    l7_buffer_len = 0;
    http_payload_len = 0;
}


void Packet_Parser::Process_Packet(u_char *args, const struct pcap_pkthdr* hdr, const u_char* buff)
{
    header = hdr;
    buffer = buff;
    packet_len = header->len;

    Parse_IP();
    Parse_TCP();
    if (HTTP_Payload_Exists())
    {
        Parse_HTTP();
    }

    // Process further only if there is text segment
    if (http_text_fragment.length())
    {
        // Get Associated flow
        Flow *flow = flows_handler.Get_Flow(ack_number);
        if (flow)
        {
            // Check if reassembly is done
            if (flow->Reassembly_Done())
            {
                std::string http_payload_decompressed;

                if (flow->Is_GZip_Compressed())
                {
                    http_payload_decompressed = Decompress_String(flow->Get_Payload());
                }
                else
                {
                    http_payload_decompressed = flow->Get_Payload();
                }

                // Check if payload has to be reported
                static std::string alert(""); 
                alert = reporter.Alert(http_payload_decompressed);
                if (alert.length() > 0)
                {
                    std::cout << "Keyword = " << alert << " | ";
                    std::cout << "IP = " << source_ip << " | ";
                    std::cout << "URL = " << url_mapper.Get_URL(source_ip) << "\n";
                }

                // All done. Remove flow.
                flows_handler.Remove_Flow(ack_number);
            }
        }
    }
}


void Packet_Parser::Parse_IP()
{
    struct sockaddr_in source, dest;

    ip_header = (struct iphdr*)(buffer + eth_header_len);
    ip_header_len = (unsigned short)ip_header->ihl*4;
    ip_total_len = ntohs(ip_header->tot_len);

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    source_ip = inet_ntoa(source.sin_addr);

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;
    dest_ip = inet_ntoa(dest.sin_addr);
}


void Packet_Parser::Parse_TCP()
{
    tcp_header = (struct tcphdr*)(buffer + eth_header_len + ip_header_len);
    tcp_header_len = (unsigned int)tcp_header->doff*4;

    ip_payload_len = ip_total_len - ip_header_len - tcp_header_len;
    source_port = ntohs(tcp_header->source);
    dest_port = ntohs(tcp_header->dest);
    ack_number = ntohl(tcp_header->ack_seq);
}


void Packet_Parser::Parse_HTTP()
{
    const u_char *payload = buffer + eth_header_len + ip_header_len + tcp_header_len;
    l7_buffer_len = packet_len - eth_header_len - ip_header_len - tcp_header_len;
    const std::string l7_buffer = std::string((char *)payload, l7_buffer_len);

    if (source_port == 80)
    {   // Process Incoming Packet
        std::regex rgx("Content-Length: (\\d*)");
        std::smatch match;
        if (std::regex_search(l7_buffer.begin(), l7_buffer.end(), match, rgx))
        { // First Segment
            http_payload_len = stoi(match[1]);

            // Skip JPEG segment
            std::size_t found = l7_buffer.find("Content-Type: image/jpeg");
            if (found != std::string::npos)
            {
                return;
            }
            // Skip PNG segment
            found = l7_buffer.find("Content-Type: image/x-icon");
            if (found != std::string::npos)
            {
                return;
            }

            // Check if data is GZIP compressed or not
            found = l7_buffer.find("Content-Encoding: gzip");
            if (found!=std::string::npos)
            {
                gzip_compressed = true;
            }
            else
            {
                gzip_compressed = false;
            }

            // Find data start position
            found = l7_buffer.find("\r\n\r\n");
            if (found!=std::string::npos)
            {
                found += 4;
            }


            std::size_t data_payload_len = (size_t)l7_buffer_len - found;
            http_text_fragment = l7_buffer.substr(found, data_payload_len);

            // Create New Flow
            Flow *flow = new Flow();
            flow->Set_IPs(source_ip, dest_ip);
            flow->Set_Ports(source_port, dest_port);
            flow->Set_Ack_Num(ack_number);
            flow->Set_Payload_Len(http_payload_len);
            flow->Payload_Append(http_text_fragment);
            flow->Set_Compression(gzip_compressed);

            flows_handler.Add_Flow(ack_number, flow);
        }
        else
        {   // Remaining Segment
            http_text_fragment = l7_buffer;

            // Add to existing flow
            Flow *flow = flows_handler.Get_Flow(ack_number);
            if (flow)
            {
                if (flow->Flow_Match(source_ip, dest_ip, source_port, dest_port, ack_number))
                {
                    flow->Payload_Append(http_text_fragment);
                }
            }
        }
    }
    else
    {   // Process Outgoing Packet
        std::smatch match;
        std::regex rgx;

        rgx = std::regex("Host: (.*)");
        if (std::regex_search(l7_buffer.begin(), l7_buffer.end(), match, rgx))
        {   // First Segment
            url_base = (std::string)match[1];
        }

        rgx = std::regex("GET (.*) HTTP");
        if (std::regex_search(l7_buffer.begin(), l7_buffer.end(), match, rgx))
        {   // First Segment
            url_endpoint = (std::string)match[1];
        }

        url = url_base + url_endpoint;
        url_mapper.Add_URL(dest_ip, url);
    }
}


bool Packet_Parser::HTTP_Payload_Exists()
{
    return ((ip_payload_len > 0) ? true : false);
}


std::string Packet_Parser::Decompress_String(const std::string& str)
{
    z_stream zs;  // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, 31) != Z_OK)
        throw(std::runtime_error("inflateInit failed while decompressing."));

    zs.next_in = (Bytef*)str.data();
    zs.avail_in = str.size();

    int ret;
    char outbuffer[32768];
    std::string outstring;

    // get the decompressed bytes blockwise using repeated calls to inflate
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (outstring.size() < zs.total_out) {
            outstring.append(outbuffer,
                             zs.total_out - outstring.size());
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) { // an error occurred that was not EOF
        std::cout << "Exception during zlib decompression: (" << ret << ") " << zs.msg; 
        return "";
    }

    return outstring;
}
