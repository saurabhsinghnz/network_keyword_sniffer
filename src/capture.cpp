#include "capture.hpp"


Packet_Parser* Capture::pkt_parser = new Packet_Parser();

Capture::Capture()
{
}


void Capture::Get_Capture_Device()
{
    char errbuf[100], devs[100][100];
    int count = 1, n;

    std::cout << "Finding available devices ... ";

    if( pcap_findalldevs( &alldevsp , errbuf) )
    {   
        std::cout << "Error finding devices : " << errbuf;
        exit(1);
    }   
    std::cout << "Done";

    //Print the available devices
    std::cout << "\nAvailable Devices are :\n";
    for(device=alldevsp; device != NULL; device = device->next)
    {
        // cout crashes stdout while printing null, hence using printf
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    //Ask user which device to sniff
    std::cout << "\n\nEnter the number of the device you want to sniff : ";
    std::cin >> n;
    devname = devs[n];
}


void Capture::Open_Capture_Device()
{
    //Open the device for sniffing
    std::cout << "Opening device " << devname << " for sniffing ... ";
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

    if (handle == NULL)
    {
        std::cout << "Couldn't open device " << devname << " : " << errbuf << "\n";
        exit(1);
    }
    std::cout << "Done\n";
}


int Capture::Set_Capture_Filter(char filter_exp[])
{
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    std::cout << "Setting filter : " << filter_exp << " ... ";
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        std::cout << "Bad filter - " << pcap_geterr(handle) << "\n";
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cout << "Error setting filter - " << pcap_geterr(handle) << "\n";
        return 1;
    }
    std::cout << "Done\n";
    return 0;
}


int Capture::Start(char filter_exp[])
{
    Get_Capture_Device();
    Open_Capture_Device();
    if (Set_Capture_Filter(filter_exp))
    {
        return 1;
    }

    //Put the device in sniff loop
    pcap_loop(handle , -1 , Capture::Process_Packet, NULL);

    return 0;
}


void Capture::Process_Packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    pkt_parser->Process_Packet(args, header, buffer);
}
