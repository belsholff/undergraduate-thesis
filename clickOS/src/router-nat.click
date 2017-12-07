// Author: Felipe Belsholff
// Date: nov 23, 2017
//
// A click router with simple outgoing traffic NAT, based on Click examples from
//https://github.com/kohler/click/blob/57177d28f308f3bd35e83133a74a5b77a8338e96/conf/fake-iprouter.click
//https://github.com/kohler/click/blob/57177d28f308f3bd35e83133a74a5b77a8338e96/conf/mazu-nat.click
//
// This NAT doesn't fully complain with UDP transport packets up to 1472 bytes,
//or fragmented ones previously routed, because recalculate checksum will cost a
//lot of human energy and resources to collect UDP packets, sorting, rebuilding
//original UDP packet, do checksum recalculate and split it again to then route.
//Checksum in UDP packets are optional, so in this case, if the developed
//application ignores it, everything could works.
// More datailed information in:
//1- http://www.ciscopress.com/articles/article.asp?p=25273&seqNum=3
//2- https://stackoverflow.com/questions/43600295/update-udp-checksum-in-fragmented-packets
//3- https://notes.shichao.io/tcpv1/figure_10-9.png
// Note: For TCP implementations with TCP/IP, this question was handled.
//
// For better comprehension, please use clicky GUI program to graphic
//representation of packet flow.
//
// When you read "definition", please do it means "declaration and definition".
//
// To complaining this, I virtualized some machines with Xen Project and built
//my router at ClickOS. Networking was bridged.
// Host:
//        xenbr0, 00:0C:29:BE:81:90, 192.168.0.94
//        xenbr1, FE:FF:FF:FF:FF:FF
//        xenbr2, FE:FF:FF:FF:FF:FF
// Router:
//        0, 00:16:3E:4F:D6:95, 192.168.0.74, connect to xenbr0 by Xen .cfg
//        1, 00:15:17:15:5D:21, 192.168.251.1, connect to xenbr1 by Xen .cfg
//        2, 00:15:17:15:5D:31, 192.168.252.1, connect to xenbr2 by Xen .cfg
// 251.2 machine:
//        eth0, 08:00:27:D5:1D:42, 192.168.251.2, connect to xenbr1 by Xen .cfg
// 252.2 machine:
//        eth0, 08:00:27:94:63:EE, 192.168.252.2, connect to xenbr2 by Xen .cfg
//
// Networks are centralized across Router.
// 192.168.0.0/23 is my lab network;
// 192.168.251.0/24 is a local network in virtualized enviromment;
// 192.168.252.0/24 same as above;
//
// Traffic flows from 251.0 and 252.0 to 0.0, using ping or iperf command, for
//example. Outgoing flow arrives to any machine in destination network, checked
//with tcpdump/wireshark. It's answers are correctly translates by
//IPAddrRewriter, re-routed and delevered.

// PS1: If you try to play tests with this code in a Click enviroment instance,
//be careful with Linux network stack in TCP connections. It can close
//connections when receive incomming answers that it haven't did (it's right at
//normal case), but in this case, Click network stack was responsible by the TCP
//request. Both stacks receives packets, shakes, everything. When it occours,
//Linux stack send RST flags in TCP packets asking to close this connection in
//both sides (cli->srv - by Linux - and after this, srv->cli).

// PS2: FTP support was not implemented yet. See the second link of this file
//(mazu-nat)to understand why, but basically that envolves TCP 23 FTP control
// port.

// Checar gw colocado aqui. ip        gw            ipnet             mac
AddressInfo(net251 192.168.251.1 192.168.251.1 192.168.251.0/24 00:15:17:15:5D:21,
            net252 192.168.252.1 192.168.252.1 192.168.252.0/24 00:15:17:15:5D:31,
            net0 192.168.0.74 192.168.0.254 192.168.0.0/23 00:16:3E:4F:D6:95
);

//Classifing frames using layer 2 codes. One classifier per existing network.
//Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
classifier0, classifier251, classifier252 :: Classifier(12/0806 20/0001,
                                                        12/0806 20/0002,
                                                        12/0800,
                                                        -
);

// Source packets output to layer 2 classifiers input 0.
FromDevice(0) -> [0]classifier0;
FromDevice(1) -> [0]classifier251;
FromDevice(2) -> [0]classifier252;

// Queue definition and connection to sink input 0.
out0 :: Queue(1024) -> ToDevice(0);
out251 :: Queue(1024) -> ToDevice(1);
out252 :: Queue(1024) -> ToDevice(2);

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
// MAC destination previously asked.
arpq0 :: ARPQuerier(net0) -> out0;
arpq251 :: ARPQuerier(net251) -> out251;
arpq252 :: ARPQuerier(net252) -> out252;

// Deliver ARP responses to ARP queriers as well as Linux.
classifier0[1] -> [1]arpq0;
classifier251[1] -> [1]arpq251;
classifier252[1] -> [1]arpq252;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
// MAC address It could be more than one per MAC address. It's useful for
//network visibility by anothers and vice versa.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
classifier0[0] -> ARPResponder(net0) -> out0;
classifier251[0] -> ARPResponder(net251) -> out251;
classifier252[0] -> ARPResponder(net252) -> out252;

// Static IP table definition. It going to send matched packets to respective
//outputs:
// 0: packets for this machine.
// 1: packets for 192.168.251.
// 2: packets for 192.168.252.
// 3: packets for outside, using a gateway.
srouter :: StaticIPLookup(net251:ip 0,
                          net251:bcast 0,
                          192.168.251.0/32 0,
                          net252:ip 0,
                          net252:bcast 0,
                          192.168.252.0/32 0,
                          net0:ip 0,
                          net0:bcast 0,
                          192.168.0.0/32 0,
                          net251:ipnet 1,
                          net252:ipnet 2,
                          net0:ipnet 3, //pacotes para a rede não vão ao gw.
                          0.0.0.0/0 192.168.0.254 3
);

// Simple NAT function. Rewrite packets that cames on it's input ports based on
//some rules previously defined. if no one rules has been matched,
//IPAddrRewriter follow a default behavior previously setted. For example,
//"pattern", "drop", "pass".
rewriter :: IPAddrRewriter(pattern net0 - 0 1,
                           drop,
                           pass 2
);

// Just telling to interpreter be calm down. It asks to connect every input port
//defined. In this case, I'm using it because input and output ports are created
//in pairs and I need the output port.
Idle -> [1]rewriter;

// NAT operation modifies IPv4 headers used to generate TCP and UDP checksuns.
//Here I'm filtering these packets and, when is possible, recalculating them.
// PS3: Look at PS1 in initial comments of this file to explanations about
//fragmented or big transport packets.
// A flow-separated filter is needed, because the paths after them are different.
//Observe!
inTransportFilter :: IPClassifier(tcp, udp, -);
outTransportFilter :: IPClassifier(tcp, udp, -);

// Ethernet header unwrapping definition, followed for an IP header checking
//that drop any invalid source IP packets, even those broadcasts spreadings
//(when broadcasts are source address). After this, packets are delivered to
//static routing.
ip :: Strip(14) -> CheckIPHeader //Deveria setar ICMPError - parameter problem?
                -> [0]srouter;

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network. Another annotation mark that frame as IPv4 protocol.
//Click system needs it to use ToHost, frames are directed to unwrapping.
classifier0[2] -> Print('rede0') -> Paint(0) -> ip;
classifier251[2] -> Print('rede251') -> Paint(1) -> ip;
classifier252[2] -> Print('rede252') -> Paint(2) -> ip;

// IP packets for this machine. What do you like to do? Me: Discard.
// Before this, packets from external network needs to be translated by NAT.
//They are redirected to rewriter to inspect this.
srouter[0] -> Print('Pode ser para subredes!') -> [2]rewriter;

//Here are packets destinated to Router. We presume that will only comes ICMP
//resquests through ping. So, router can answer the resquest.
rewriter[2] -> Print('Não é para subredes!')
            -> SetPacketType(HOST)
            -> IPFilter (allow icmp type 'echo', drop all)
            -> ICMPPingResponder()
            -> [0]srouter;

// As I sad above, here are incomming NAT-ed packets. They have their checksum
//recalculated (TCP in this case, others below) and come out translated to their
//inner destination, and re-routed.
rewriter[1] -> inTransportFilter
            -> SetTCPChecksum
            -> [0]srouter;

//Same piece of code as above, but now handling with incoming UDP packets.
inTransportFilter[1] -> udpIn :: SetUDPChecksum //tratar pacotes grandes ou fragmentados;
                     -> [0]srouter;

udpIn[1] -> Print ('Pacotes UDP maiores que 1472 bytes ou fragmentados não são
                   tratados pela impossibilidade de recalcular o checksum.')
         -> Discard;

//Same as above. ICMP out here because ICMP checksum was not compromised by NAT.
inTransportFilter[2] -> Print('ICMP ou Mensagem de camada 4 desconhecida chegando!')
                     -> [0]srouter;

// Receiving packets addressed to network (0.0) and outgoing to internet and
//preparing to send to inferface destination.
// Some parts of this code repeats to others interfaces handled below.
// 1: Dropping link-level broadcasts;
// 2: Marking as outgoing flow packet. Before DropBroadcasts because it uses the
//same mecanism to mark broadcast packets.
// 3: Redirecting flow to NAT element port 0;
// 4: As shown, transport protocol filter to apply checksum recalculation to TCP;
// 5: Recalculation as mentioned above;
// 6: Duplicating packets that was marked as packets that came from same
//destination network. It's undesirable and should be notified with an ICMP
//error(see below). Packets on this situation, even through, going to devivered.
// 7: Among other things, recompute timestamp and checksum of IP packets. If
//any error happens, it going to redirects those packets to output 1 (see
//below) and send a source notification through ICMP packet for each one
// 8: It decrement Time-To-Live propriety of IP packets. If TTL was expired,
//this packet is redirected to output 1 and an ICMP error raise.
// 9: It fragment IP packets to choose n bytes and set fragmented bit. If a
//non-fragment bit have been set or any other error, ICMP error will raise after
//redirection to output 1.
// 10: Sending packets to ARP Querier input 0 to be wrap and set link level (MAC)
//address correctly.
srouter[3] -> DropBroadcasts // DropBroadcasts ignora broadcasts apartir de uma
                             //anotação (SetPacketType) feita pelo FromDevice.
                             // Em caso de falha, ver CheckIPHeader.
           -> SetPacketType(OUTGOING)
           -> [0]rewriter
	       -> outTransportFilter
	       -> SetTCPChecksum
           -> cp0 :: PaintTee(0)
           -> gio0 :: IPGWOptions(net0)
           -> dt0 :: DecIPTTL
           -> fr0 :: IPFragmenter(1500)
           -> [0]arpq0;

//Same piece of code as above, but now handling with outgoing UDP packets.
outTransportFilter[1] -> udpOut :: SetUDPChecksum -> cp0;

udpOut[1] -> Print ('Pacotes UDP maiores que 1472 bytes ou fragmentados não são
                   tratados pela inviabilidade de recalcular o checksum.')
         -> cp0;

//Same as above. ICMP out here because ICMP checksum was not compromised by NAT.
outTransportFilter[2] -> Print('ICMP ou Mensagem de camada 4 desconhecida saíndo!')
                      -> cp0;

// Receiving packets addressed to network (251.0) and preparing to send to
//inferface destination.
srouter[1] -> DropBroadcasts
           -> SetPacketType(OUTGOING) //Antes do DropBroadcasts por causa da anotação de broadcast.
           -> cp1 :: PaintTee(1)
           -> gio1 :: IPGWOptions(net251)
           -> dt1 :: DecIPTTL
           -> udpcs1 :: SetTCPChecksum
           -> fr1 :: IPFragmenter(1500)
           -> [0]arpq251;

// Receiving packets addressed to network (252.0) and preparing to send to
//inferface destination.
srouter[2] -> DropBroadcasts
           -> SetPacketType(OUTGOING)
           -> cp2 :: PaintTee(2)
           -> gio2 :: IPGWOptions(net252)
           -> dt2 :: DecIPTTL
           -> udpcs2 :: SetTCPChecksum
           -> fr2 :: IPFragmenter(1500)
           -> [0]arpq252;

// DecIPTTL[1] emits packets with expired TTLs.
// Reply with ICMPs. Rate-limit them?
dt0[1] -> ICMPError(net0, timeexceeded) -> [0]srouter;
dt1[1] -> ICMPError(net251, timeexceeded) -> [0]srouter;
dt2[1] -> ICMPError(net252, timeexceeded) -> [0]srouter;

// Send back ICMP UNREACH/NEEDFRAG messages on big packets with DF set.
// This makes path mtu discovery work.
fr0[1] -> ICMPError(net0, unreachable, needfrag) -> [0]srouter;
fr1[1] -> ICMPError(net251, unreachable, needfrag) -> [0]srouter;
fr2[1] -> ICMPError(net252, unreachable, needfrag) -> [0]srouter;

// Send back ICMP Parameter Problem messages for badly formed
// IP options. Should set the code tonet251 point to the
// bad byte, but that's too hard.
gio0[1] -> ICMPError(net0, parameterproblem) -> [0]srouter;
gio1[1] -> ICMPError(net251, parameterproblem) -> [0]srouter;
gio2[1] -> ICMPError(net252, parameterproblem) -> [0]srouter;

// Send back an ICMP redirect if required.
cp0[1] -> ICMPError(net0, redirect, host) -> [0]srouter;
cp1[1] -> ICMPError(net251, redirect, host) -> [0]srouter;
cp2[1] -> ICMPError(net252, redirect, host) -> [0]srouter;

// Unknown ethernet type numbers.
classifier0[3] -> Discard;
classifier251[3] -> Discard;
classifier252[3] -> Discard;
