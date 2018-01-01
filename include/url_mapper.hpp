#ifndef URL_MAPPER_H
#define URL_MAPPER_H

#include <map>


class URL_Mapper {
    private:
        // Map of URLs
        // Key is IP Address
        // Value is URL
        std::map<std::string, std::string> urls;

    public:
        void Add_URL(std::string, std::string);
        std::string Get_URL(std::string ip_address);
};

#endif
