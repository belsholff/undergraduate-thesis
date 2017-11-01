// Author: Felipe Belsholff
// Date: sep 14, 2017
// A click router without NAT, based on Click examples from
//http://read.cs.ucla.edu/click/examples/fake-iprouter.click
// A sniffer was connected at 251.0/24 network and is delivering incomming and
//outgoing packets to 252.0/24 network quietly.
//
// For better comprehension, please use clicky GUI program to visualize packet
//flow.
//
// When you read "definition", please do it means "declaration and definition".
//
// To complaining this, I used VirtualBox's machines:
// Router:
//        enp0s3, 08:00:27:43:9C:7F, 172.16.30.155
//        enp0s8, 08:00:27:BF:8F:22, 192.168.251.1
//        enp0s9, 08:00:27:C2:45:2B, 192.168.252.1
// 251.2 machine:
//        eth0, 08:00:27:D5:1D:42, 192.168.251.2
// 251.3 machine:
//        eth0, 08:00:27:0C:5C:EE, 192.168.251.3
// 252.2 machine:
//        eth0, 08:00:27:94:63:EE, 192.168.252.2
//
// Networks are centralized across Router.
// 172.16.30.0/23 is my lab network;
// 192.168.251.0/24 is a local network in virtualized enviromment;
// 192.168.252.0/24 same as above;
//
// Traffic flows from 251.0 to 30.0, using ping or iperf command, for example.
//Outgoing flow arrives to any machine in dst network, checked with
//tcpdump/wireshark. Incomming answers only arrives if a route at 30.0's machine
//was previously configured to send to our Router VM.

AddressInfo(
    net251 192.168.251.1 192.168.251.0/24 08:00:27:BF:8F:22,
    net252 192.168.252.1 192.168.252.0/24 08:00:27:C2:45:2B,
    net172 172.16.30.155 172.16.30.0/23 08:00:27:43:9C:7F,
    int_machine 192.168.251.2 192.168.251.0/24,
);

//Classifing frames using Ethernet codes. Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier172, classifier251, classifier252 :: Classifier(
    12/0806 20/0001,
    12/0806 20/0002,
    12/0800,
    -
);

// Source packets output to Ethernet classifiers input 0.
FromDevice(enp0s3) -> [0]classifier172;
FromDevice(enp0s8) -> [0]classifier251;
FromDevice(enp0s9) -> [0]classifier252;

// Queue definition and connection to sink input 0.
out172 :: Queue(1024) -> ToDevice(enp0s3);
out251 :: Queue(1024) -> ToDevice(enp0s8);
out252 :: Queue(1024) -> ToDevice(enp0s9);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq172 :: ARPQuerier(net172) -> out172;
arpq251 :: ARPQuerier(net251) -> out251;
arpq252 :: ARPQuerier(net252) -> out252;

// Deliver ARP responses to ARP queriers as well as Linux. Tee() is a packet
//multiplier and delive each copy in certain number of output ports.
// Aparentemente não há necessidade desses diversos classificadores e cópias de
//pacotes, pois tudo poderia entrar em um só ARPResponder com diferentes
//atributos.
classifier172[1] -> [1]arpq172;
classifier251[1] -> [1]arpq251;
classifier252[1] -> [1]arpq252;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for network
//visibility by anothers and vice versa.
// Remember that the Querier needs incoming routes to and outgoing from this
//machine.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
classifier172[0] -> ARPResponder(net172) -> out172; //checar se os pacotes estão
classifier251[0] -> ARPResponder(net251) -> out251; //[trafegando mesmo sem o
classifier252[0] -> ARPResponder(net252) -> out252; //[proxy ARP;

// Static IP table definition. It going to send matched packets to respective
//outputs:
// 0: packets for this machine.
// 1: packets for 192.168.251.
// 2: packets for 192.168.252.
// 3: packets for outside.
srouter :: StaticIPLookup(192.168.251.1/32 0,
                     192.168.251.255/32 0,
                     192.168.251.0/32 0,
                     192.168.252.1/32 0,
                     192.168.252.255/32 0,
                     192.168.252.0/32 0,
                     172.16.30.155/32 0, //volta por aqui
                     172.16.30.255/32 0,
                     172.16.30.0/32 0,
                     192.168.251.0/24 1,
                     192.168.252.0/24 2,
                     0.0.0.0/0 3 //vai por aqui
);

rewriter :: IPAddrRewriter(pattern net172 - 0 1, // Aparentemente o Linux está 
                                                 //mandando RST por não possuir
                                                 //conexões que o Click criou
                       drop,
                       pass 2
);
Idle -> [1]rewriter;

// Unwrapping Ethernet header definition, followed for an IP header checking
//that drop any invalid source IP packets, even those broadcats spreadings (when
//broadcasts are source address), and so on, filtered packets are delivered to
//static routing.
// REMEMBER: there's not public IP passing through this router, until it's
//behind local networks as we see here with 172.16 network.
ip ::   Strip(14)
     -> CheckIPHeader // Se tratando de um router com NAT, não se pode definir
     -> [0]srouter;   //[os IPs de INTERFACES, ao mesmo tempo que é necessário
                      //[forçar a verificação dos broadcasts para evitar nuvens
                      //[de broadcasts, além da integridade dos pacotes.
                      //[Verificar se DropBroadcasts resolve essa questão.

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network.
// After annotations, frames are directed to unwrapping.
classifier172[2] -> Paint(0) -> MarkIPHeader -> ip;
classifier251[2] -> Paint(1) -> MarkIPHeader -> ip;
classifier252[2] -> Paint(2) -> MarkIPHeader -> ip;

// IP packets for this machine. What do you like to do? Me: Discard.
// ToHost expects ethernet packets, so cook up a fake header.
// Problema a resolver quando for estritamente necessário que os roteadores
//recebam os pacotes direcionados a ele.
// srouter[0] -> EtherEncap(0x0800, 1:1:1:1:1:1, net251) -> Discard;
// srouter[0] -> EtherEncap(0x0800, 1:1:1:1:1:1, net251) -> ToHost(enp0s8);
srouter[0] -> Print('Resposta chegou!') -> [2]rewriter;
rewriter[2] -> EtherEncap(0x0800, 1:1:1:1:1:1, net251) -> Discard;

// Receiving packets addressed to 251.0/24 network and preparing to send to
//inferface destination.
// 1: Dropping link-level broadcasts.
// 2: Duplicating packets that was marked as packets that came from same
//destination network. It's undesirable and should be notified with an ICMP
//error(see below). Packets on this situation, even through, going to devivered.
// 3: Among other things, recompute timestamp and checksum of IP packets. If
//any error happens, it going to redirects those packets to output 1 (see
//below) and send a source notification through ICMP packet for each one
// 4: It change the source IP of packets that came from local networks if an
//annotation require this. It also recomputes packets' checksum.
// 5: It decrement Time-To-Live propriety of IP packets. If TTL was expired,
//this packet is redirected to output 1 and an ICMP error raise.
// 6: It fragment IP packets to choose n bytes and set fragmented bit. If a
//non-fragment bit have been set or any other error, ICMP error will raise after
//redirection to output 1.
// 7: Just a print to console, showing a string and writing packets content.
// 8: Sending packets to ARP Querier input 0 to be wrap and set link level (MAC)
//address correctly.
srouter[3] -> DropBroadcasts //caso não esteja sendo efetivo, o CheckIPHeader pode fazer serviço semelhante com a opção INTERFACES ou BADSRC;
                             //DropBroadcasts ignora broadcasts apartir de uma anotação (SetPacketType) feita pelo FromDevice.
           -> [0]rewriter
           -> Print('Antes do Rewriter!')
           -> cp0 :: PaintTee(0)
           -> gio0 :: IPGWOptions(172.16.30.155)
//           -> FixIPSrc(172.16.30.155) //ver como configura as anotações pra trocar os IPs
           -> dt0 :: DecIPTTL
           -> fr0 :: IPFragmenter(1492)
           -> [0]arpq172;

rewriter[1] -> [0]srouter;

srouter[1] -> DropBroadcasts
      -> cp1 :: PaintTee(1)
      -> gio1 :: IPGWOptions(192.168.251.1)
//      -> FixIPSrc(192.168.251.1)
      -> dt1 :: DecIPTTL
      -> fr1 :: IPFragmenter(1492)
      -> [0]arpq251;

srouter[2] -> DropBroadcasts
      -> cp2 :: PaintTee(2)
      -> gio2 :: IPGWOptions(192.168.252.1)
//      -> FixIPSrc(192.168.252.1)
      -> dt2 :: DecIPTTL
      -> fr2 :: IPFragmenter(1492)
      -> [0]arpq252;

// DecIPTTL[1] emits packets with expired TTLs.
// Reply with ICMPs. Rate-limit them?
dt0[1] -> ICMPError(172.16.30.155, timeexceeded) -> [0]srouter;
dt1[1] -> ICMPError(192.168.251.1, timeexceeded) -> [0]srouter;
dt2[1] -> ICMPError(192.168.252.1, timeexceeded) -> [0]srouter;

// Send back ICMP UNREACH/NEEDFRAG messages on big packets with DF set.
// This makes path mtu discovery work.
fr0[1] -> ICMPError(172.16.30.155, unreachable, needfrag) -> [0]srouter;
fr1[1] -> ICMPError(192.168.251.1, unreachable, needfrag) -> [0]srouter;
fr2[1] -> ICMPError(192.168.252.1, unreachable, needfrag) -> [0]srouter;

// Send back ICMP Parameter Problem messages for badly formed
// IP options. Should set the code to point to the
// bad byte, but that's too hard.
gio0[1] -> ICMPError(172.16.30.155, parameterproblem) -> [0]srouter;
gio1[1] -> ICMPError(192.168.251.1, parameterproblem) -> [0]srouter;
gio2[1] -> ICMPError(192.168.252.1, parameterproblem) -> [0]srouter;

// Send back an ICMP redirect if required.
cp0[1] -> ICMPError(172.16.30.155, redirect, host) -> [0]srouter;
cp1[1] -> ICMPError(192.168.251.1, redirect, host) -> [0]srouter;
cp2[1] -> ICMPError(192.168.252.1, redirect, host) -> [0]srouter;

// Unknown ethernet type numbers.
classifier172[3] -> Print('unknown0') -> Discard;
classifier251[3] -> Print('unknown1') -> Discard;
classifier252[3] -> Print('unknown2') -> Discard;
