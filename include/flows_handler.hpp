#ifndef FLOWS_HANDLER_H
#define FLOWS_HANDLER_H

#include <map>
#include "flow.hpp"


class Flows_Handler {
    private:
        // Map of Flows
        // Key is acknowledgement number
        // Value is pointer to flow object
        std::map<unsigned int, Flow*> flows;

    public:
        void Add_Flow(unsigned int ack_number, Flow* flow);
        void Remove_Flow(unsigned int ack_number);
        Flow* Get_Flow(unsigned int ack_number);
};

#endif
