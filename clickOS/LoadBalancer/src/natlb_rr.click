// Author: Felipe Belsholff
// Date: Dez 7, 2017

// Organizing IPs, networks and MACs from this MicroVM. Or tagging known hosts.
//          name     ip             ipnet               mac
AddressInfo(net0 192.0.2.61     192.0.2.0/24     00:01:92:00:02:61,
            net1 172.16.40.21   172.16.0.0/12    00:01:72:16:40:21,
            fw0  192.0.2.11,
            ws1  172.16.40.55,
            ws2  172.16.80.147,
            ws3  172.16.37.181
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
classifier0, classifier1 :: Classifier(12/0806 20/0001, // 0. ARP queries
                                       12/0806 20/0002, // 1. ARP replies
                                       12/0800,         // 2. IP
                                       -                // 3. Other
);

// For both: Incoming packets from interfaces are going to layer 2 classifiers
//input 0.
FromDevice(0) -> [0]classifier0; // First network port defined in .cfg. Packets
                                 //(requests) are coming to processing.
FromDevice(1) -> [0]classifier1; // Second one. Packets are going out;

// Queue definition and connection to queue input 0. Here, packets processing
//comes push and turns to pull.
out0 :: Queue(1024) -> ToDevice(0);
out1 :: Queue(1024) -> ToDevice(1);

// ARPQuerier definition. This wraps IP packets into Ethernet frames with given
//MAC destination previously asked through ARP protocol queries.
arpq0 :: ARPQuerier(net0) -> out0;
arpq1 :: ARPQuerier(net1) -> out1;

// Delivering ARP responses to ARP queriers.
classifier0[1] -> [1]arpq0;
classifier1[1] -> [1]arpq1;

// ARP Responder definitions. It's useful for host visibility by others in
//networks. It going to answer ARP queries with MAC address based on IP-matched.
//It could contain more than one entry, which means ARP Responders could answer
//queries about another machines and networks. ProxyARP is an application of
//this.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through queues.
classifier0[0] -> ARPResponder(net0) -> out0;
classifier1[0] -> ARPResponder(net1) -> out1;

// Mapping used to do load balancing based on Round Robin distribution, with a
//quintuple SIP, SPort, DIP, DPort and Protocol, which means that requests with
//they, are mapped to the same cluster node. It helps in the use of TCP
//connections.
// This mapping is used inside the IPRewriter element below.
// More detailed documentation about rules and this integration here:
//https://github.com/kohler/click/wiki/IPRewriter
ws_mapper :: RoundRobinIPMapper(- - ws1 - 0 1,
                                - - ws2 - 0 1,
                                - - ws3 - 0 1
);

// Simple NAT function. Rewrite packets that cames on it's input ports based on
//some rules in a table. This table receives entries by handlers or general
//lines hardcoded in arguments function. Rules are set twice at time: first one
//about incomming flow and later about outgoing one. Each flow goes out by an
//output port previously defined by rule. Hardcode lines sets inputs and outputs
//ports numbering them by its order in arguments, and are used just when there's
//no rule matched in table.
//IPRewriter hardcoded behaviors:
//1- pattern
//2- drop
//3- pass
// IPRewriter also could receive previously defined static and dinamic tables
//as SourceIPHashMapper (which is our case) or IPRewritterPatterns. More
//detailed documentation in link above.
rewriter :: IPRewriter(ws_mapper,
                       drop
);

// For both classifiers:
// Ethernet packets are stripped and comes to IP packets, that has its headers
//checked, and send to NAT/LB elements.
classifier0[2] -> Strip(14)
               -> CheckIPHeader()
               -> [0]rewriter;

classifier1[2] -> Strip(14)
               -> CheckIPHeader()
               -> [1]rewriter;

//For both rewriters:
// As I sad above, here are incomming and outgoing NAT-ed packets. They have
//their checksum recalculated (TCP in this case, others below) and come out
//ready to be send to its destination through ARPQuerier.
rewriter[0] -> SetTCPChecksum()
            -> [0]arpq1;

// Here, a default gateway needs to be set to handle packets outside of
//reachable networks. This is why SetIPAddress are used to set destination
//annotation address and transmit packets to our firewall/gateway.
rewriter[1] -> SetTCPChecksum()
            -> SetIPAddress(fw0)
            -> [0]arpq0;

// Other protocol types inside ethernet frames. They are dropped/discarded.
classifier0[3] -> Discard;
classifier1[3] -> Discard;
