#include "capture.hpp"


int main()
{
    Capture capture;
    char filter[] = "port 80";
    if (capture.Start(filter))
    {
        return 1;
    }

    return 0;
}
