// Author: Felipe Belsholff
// Date: Dez 8, 2017

//                      ip            ipnet             mac
AddressInfo(net0  10.0.0.2     10.0.0.0/24    00:15:17:15:00:02,
            net1  172.16.30.11 172.16.30.0/24 00:15:17:15:30:11,
            nat1  172.16.30.12,
            user1 10.0.0.1
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier0, classifier1 :: Classifier(12/0806 20/0001,
                                       12/0806 20/0002,
                                       12/0800,
                                       -
);

// Source packets output to layer 2 classifiers input 0.
FromDevice(0) -> [0]classifier0;
FromDevice(1) -> [0]classifier1;

// Queue definition and connection to sink input 0.
out0 :: Queue(1024) -> ToDevice(0);
out1 :: Queue(1024) -> ToDevice(1);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq0 :: ARPQuerier(net0) -> out0;
arpq1 :: ARPQuerier(net1) -> out1;

// Deliver ARP responses to ARP queriers as well as Linux.
classifier0[1] -> [1]arpq0;
classifier1[1] -> [1]arpq1;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for
//network visibility by anothers and vice versa.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
classifier0[0] -> ARPResponder(net0, nat1:ip net0:mac) -> out0; //responder pelo NAT
classifier1[0] -> ARPResponder(net1, user1:ip net1:mac) -> out1;

webfilter :: IPFilter(allow dst 172.16.30.12 && dst port 80 or 443,
                         drop all)

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network. Another annotation mark that frame as IPv4 protocol.
//Click system needs it to use ToHost, frames are directed to unwrapping.
classifier0[2] -> Strip(14) -> CheckIPHeader() -> webfilter -> [0]arpq1;
classifier1[2] -> Strip(14) -> CheckIPHeader() -> [0]arpq0;

// Other protocol types inside ethernet frames.
classifier1[3] -> Discard;
classifier2[3] -> Discard;
