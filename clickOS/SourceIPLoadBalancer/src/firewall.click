// Author: Felipe Belsholff
// Date: Dez 8, 2017

//                            ip            ipnet              mac
AddressInfo(net1        192.168.171.11 192.168.171.0/24 00:92:16:81:71:11,
            natlb1_int  192.168.171.12,
            natlb1_ext  10.0.0.3,
            user1       192.168.171.91
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier1 :: Classifier(12/0806 20/0001,
                          12/0806 20/0002,
                          12/0800,
                          -
);

// Source packets output to layer 2 classifiers input 0.
FromDevice(0) -> [0]classifier1;

// Queue definition and connection to sink input 0.
out1 :: Queue(1024) -> ToDevice(0);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq1 :: ARPQuerier(net1) -> out1;

// Deliver ARP responses to ARP queriers as well as Linux.
classifier1[1] -> [1]arpq1;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for
//network visibility by anothers and vice versa.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
classifier1[0] -> ARPResponder(net1) -> out1;

webfilter :: IPFilter(allow dst natlb1_ext && dst port 80 or 443,
                      drop all)

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network. Another annotation mark that frame as IPv4 protocol.
//Click system needs it to use ToHost, frames are directed to unwrapping.
classifier1[2] -> Strip(14)
	       -> CheckIPHeader() //ver sobre passar pacotes com IPs diferentes do IP da rede -> CheckIPHeader.
               -> webfilter
               -> SetIPAddress(natlb1_int)
	       -> IPPrint
               -> [0]arpq1;

webfilter[1] -> Print('Barrou') -> Discard;

// Other protocol types inside ethernet frames.
classifier1[3] -> Discard;
