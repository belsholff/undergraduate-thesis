// Author: Felipe Belsholff
// Date: Dez 7, 2017

//                  ip            ipnet                 mac
AddressInfo(net0 10.0.0.3       10.0.0.0/8       00:00:00:01:00:03,
            net1 192.168.171.12 192.168.171.0/24 01:92:16:81:71:12,
            net2 172.16.40.21   172.16.0.0/12    00:01:72:16:40:21,
            ws1  172.16.40.55,
            ws2  172.16.80.147,
            ws3  172.16.37.181
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier0, classifier1, classifier2 :: Classifier(12/0806 20/0001,
                                                    12/0806 20/0002,
                                                    12/0800,
                                                    -
);

// Source packets output to layer 2 classifiers input 0.
FromDevice(0) -> [0]classifier0; // Usável apenas para receber ARP replies.
FromDevice(1) -> [0]classifier1; // Não usável para receber ARP replies.
FromDevice(2) -> [0]classifier2;

// Queue definition and connection to sink input 0.
out0 :: Queue(1024) -> ToDevice(0);
out1 :: Queue(1024) -> ToDevice(1);
out2 :: Queue(1024) -> ToDevice(2);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq0 :: ARPQuerier(net1) -> out0;
// arpq1 :: ARPQuerier(net1) -> out1; // Nada IP é enviado por essa interface.
                                      // Só envia ARP replies.
arpq2 :: ARPQuerier(net2) -> out2;

// Deliver ARP responses to ARP queriers as well as Linux.
classifier0[1] -> [1]arpq0;
// classifier1[1] -> [1]arpq1; // Nada IP é enviado por essa interface.
classifier1[1] -> Discard;
classifier2[1] -> [1]arpq2;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for
//network visibility by anothers and vice versa.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
//classifier0[0] -> ARPResponder(net0) -> out0; // Testar se precisa negar o mac
                                                //da máquina destino da requisição
                                                //web para não ter conflito com
                                                //o caminho através do firewall.
                                                // Usável apenas se parte do
                                                //fluxo não passar pelo firewall.
classifier0[0] -> Discard;
classifier1[0] -> ARPResponder(net1) -> out1;
classifier2[0] -> ARPResponder(net2) -> out2;

ws_mappers :: SourceIPHashMapper(129 0xbadbeef, // Params: Nodes per machine=129; Seed=0xbadbeef
                                                // Ver esses parâmetros!
                                 - - ws1 - 0 1 101,
                                 - - ws2 - 0 1 102,
                                 - - ws3 - 0 1 103
);

// Simple NAT function. Rewrite packets that cames on it's input ports based on
//some rules previously defined. if no one rules has been matched,
//IPAddrRewriter follow a default behavior previously setted. For example,
//"pattern", "drop", "pass".
rewriter :: IPRewriter(ws_mappers,
                       drop
);

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network. Another annotation mark that frame as IPv4 protocol.
//Click system needs it to use ToHost, frames are directed to unwrapping.
classifier0[2] -> Discard;
classifier1[2] -> Strip(14) -> [0]rewriter;
classifier2[2] -> Strip(14) -> [1]rewriter;

// As I sad above, here are incomming and outgoing  NAT-ed packets. They have
//their checksum recalculated (TCP in this case, others below) and come out
//translated to their inner destination, and re-routed.
rewriter[0] -> SetTCPChecksum() -> CheckIPHeader() -> [0]arpq2;
rewriter[1] -> SetTCPChecksum() -> CheckIPHeader() -> [0]arpq0;

// Other protocol types inside ethernet frames.
classifier0[3] -> Discard;
classifier1[3] -> Discard;
classifier2[3] -> Discard;
