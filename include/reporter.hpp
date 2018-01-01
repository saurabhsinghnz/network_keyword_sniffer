#ifndef REPORTER_H
#define REPORTER_H

#include <string>
#include <fstream>
#include <list>
#include <iostream>


class Reporter {
    private:
        std::list<std::string> keywords;
        std::string filename = "keywords.txt";

    public:
        Reporter();

        std::string Alert(std::string);
};

#endif
