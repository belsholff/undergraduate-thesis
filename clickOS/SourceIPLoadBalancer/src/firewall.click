// Definition: A firewall to a web based network containing it, a NAT with Load
//Balancer, and some Web Servers and Hosts in a private network. This also acts
//as a gateway between 198.51.100.0/24 and 192.0.2.0/24 IETF defined test
//networks, where the entire "public network" are set.
// Author: Felipe Belsholff;
// Create: Dez 8, 2017;
// Last modified: Apr 20, 2018;
// Version 2.0.50;

// Organizing IPs, networks and MACs from this MicroVM. Or tagging known hosts.
//          name             ip           ipnet              mac
AddressInfo(net0        198.51.100.98 198.51.100.0/24 00:19:85:11:00:98,
            net1        192.0.2.11    192.0.2.0/24    00:01:92:00:02:11,
            natlb       192.0.2.61
);

//Classifing frames using layer 2 codes. One classifier per existing network.
                                                        // Outputs:
classifier0, classifier1 :: Classifier(12/0806 20/0001, // 0. ARP queries
                                       12/0806 20/0002, // 1. ARP replies
                                       12/0800,         // 2. IP
                                       -                // 3. Other
);

// Incoming packets going to layer 2 classifiers input 0.
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

// Delivering ARP responses to the ARP querier.
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

// Firewall application accepting only http requests to natlb from entire net0.
webFilterIN :: IPFilter(allow src net0:ipnet && dst natlb && dst port 80,
                        drop all)

// Firewall application accepting only http responses (through dynamic ports)
//to entire net0 from natlb.
// OSes dynamic ports list:
//Linux     - 32768-61000
//WinVista  - \/
//Win7      - \/
//WinSrv08  - \/
//FreeBSD4.6- \/
//IANA      - 49152-65535
//BSD       - \/
//WindowsXP - \/
//WinSrv03  - 1025-5000
//Win8      - \/
//Win8.1    - \/
//Win10     -  ?
webFilterOUT :: IPFilter(allow src natlb && dst net0:ipnet && dst port >= 32768 && dst port <= 61000,
                         drop all) //Como fazer para ser stateful?

// For both classifiers:
// Ethernet packets are stripped and comes to IP packets, that has its headers
//checked, filtered by incomming firewall, and encapsulated by ARP querier based
//on its destination address.
classifier0[2] -> Strip(14)
               -> CheckIPHeader()
               -> webFilterIN       // Não é necessário setar a anotação para o
//               -> IPPrint('IN:')  //IP de destino, pois o pacote tem seu
               -> [0]arpq1;         //destino atingível.

classifier1[2] -> Strip(14)
               -> CheckIPHeader()
               -> webFilterOUT      // Não é necessário setar a anotação para o
//               -> IPPrint('OUT:') //IP de destino, pois o pacote tem seu
               -> [0]arpq0;         //destino atingível.

// Other protocol types inside ethernet frames. They are dropped/discarded.
classifier0[3] -> Discard;
classifier1[3] -> Discard;
