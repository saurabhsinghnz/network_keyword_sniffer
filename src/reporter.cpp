#include "reporter.hpp"


Reporter::Reporter() {
    std::ifstream ifs(filename);
    if (not ifs.good())
    {
        std::cout << "Could not open file " << filename << "\n";
        exit(1);
    }
    std::string keyword;

    while(!ifs.eof()) 
    {
        getline(ifs, keyword);
        keywords.push_back (keyword);
    }
}


std::string Reporter::Alert(std::string http_payload) {
    static std::string keyword;
    static std::size_t found;

    for (std::list<std::string>::iterator keyword=keywords.begin();
         keyword != keywords.end();
         ++keyword)
    {
        found = http_payload.find(*keyword);
        if (found != std::string::npos)
        {
            return *keyword;
        }
    }
    return std::string("");
}
