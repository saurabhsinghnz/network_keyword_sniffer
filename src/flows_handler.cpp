#include "flows_handler.hpp"


void Flows_Handler::Add_Flow(unsigned int ack_number, Flow* flow)
{
    flows[ack_number] = flow;
}


void Flows_Handler::Remove_Flow(unsigned int ack_number)
{
    Flow* flow = flows[ack_number];
    delete flow;
    flows.erase(ack_number);
}


Flow* Flows_Handler::Get_Flow(unsigned int ack_number)
{
    if (flows.find(ack_number) == flows.end())
    {
        return NULL;
    }
    else
    {
        return flows[ack_number];
    }
}
