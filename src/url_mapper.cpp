#include "url_mapper.hpp"


void URL_Mapper::Add_URL(std::string ip_address, std::string url)
{
    urls[ip_address] = url;
}


std::string URL_Mapper::Get_URL(std::string ip_address)
{
    if (urls.find(ip_address) == urls.end())
    {
        return NULL;
    }
    else
    {
        return urls[ip_address];
    }
}
