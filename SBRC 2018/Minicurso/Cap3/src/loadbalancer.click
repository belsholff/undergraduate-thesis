// Author: Felipe Belsholff
// Date: Dez 12, 2017

//                    ip           ipnet            mac
AddressInfo(net1 172.16.30.12  172.16.30.0/24  00:15:17:15:30:12,
            net2 192.168.40.21 192.168.40.0/24 00:15:17:15:40:21,
            lb1  192.168.40.22 192.168.40.0/24 00:15:17:15:40:22
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier1, classifier2 :: Classifier(12/0806 20/0001,
                                       12/0806 20/0002,
                                       12/0800,
                                       -
);

// Source packets output to layer 2 classifiers input 0.
FromDevice(0) -> [0]classifier1;
FromDevice(1) -> [0]classifier2;

// Queue definition and connection to sink input 0.
out1 :: Queue(1024) -> ToDevice(0);
out2 :: Queue(1024) -> ToDevice(1);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq1 :: ARPQuerier(net1) -> out1;
arpq2 :: ARPQuerier(net2) -> out2;

// Deliver ARP responses to ARP queriers as well as Linux.
classifier1[1] -> [1]arpq1;
classifier2[1] -> [1]arpq2;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for
//network visibility by anothers and vice versa.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
classifier1[0] -> ARPResponder(net1) -> out1;
classifier2[0] -> ARPResponder(net2) -> out2;

// Simple NAT function. Rewrite packets that cames on it's input ports based on
//some rules previously defined. if no one rules has been matched,
//IPAddrRewriter follow a default behavior previously setted. For example,
//"pattern", "drop", "pass".
rewriter :: IPAddrRewriter(pattern net2 lb1 0 1,
                           drop
);

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network. Another annotation mark that frame as IPv4 protocol.
//Click system needs it to use ToHost, frames are directed to unwrapping.
classifier1[2] -> Strip(14) -> CheckIPHeader() -> [0]rewriter;
classifier2[2] -> Strip(14) -> CheckIPHeader() -> [1]rewriter;

// As I sad above, here are incomming and outgoing  NAT-ed packets. They have
//their checksum recalculated (TCP in this case, others below) and come out
//translated to their inner destination, and re-routed.
rewriter[0] -> SetTCPChecksum() -> [0]arpq2;
rewriter[1] -> SetTCPChecksum() -> [0]arpq1;

// Other protocol types inside ethernet frames.
classifier1[3] -> Discard;
classifier2[3] -> Discard;
