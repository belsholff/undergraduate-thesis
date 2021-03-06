// Author: Felipe Belsholff
// Date: sep 14, 2017
// A click router without NAT, based on Click examples from
//http://read.cs.ucla.edu/click/examples/fake-iprouter.click
// A ICMP filter was connected at 251.0/24 network and is blocking these
//outgoing packets just to 30.0/23 network quietly.
//
// For better comprehension, please use clicky GUI program to visualize packet
//flow.
//
// When you read "definition", please do it means "declaration and definition".
//
// To complaining this, I used VirtualBox's machines:
// Router:
//        eth0, 08:00:27:43:9C:7F, 172.16.30.162
//        eth1, 08:00:27:BF:8F:22, 192.168.251.1
//        eth2, 08:00:27:C2:45:2B, 192.168.252.1
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

define($IP0 172.16.30.162);
define($IP1 192.168.251.1);
define($IP2 192.168.252.1);
define($MAC0 08:00:27:43:9C:7F);
define($MAC1 08:00:27:BF:8F:22);
define($MAC2 08:00:27:C2:45:2B);

// Defines didn't work here. Maybe AddressInfo could be.
// Sources and Sinks definitions
source0 :: FromDevice(eth0);
sink0   :: ToDevice(eth0);

source1 :: FromDevice(eth1);
sink1   :: ToDevice(eth1);

source2 :: FromDevice(eth2);
sink2   :: ToDevice(eth2);

// Classifing frames using Ethernet codes. Outputs:
// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
c0 :: Classifier(12/0806 20/0001,
                  12/0806 20/0002,
                  12/0800,
                  -);

c1 :: Classifier(12/0806 20/0001,
                  12/0806 20/0002,
                  12/0800,
                  -);

c2 :: Classifier(12/0806 20/0001,
                  12/0806 20/0002,
                  12/0800,
                  -);

// Source packets output to Ethernet classifiers input 0.
source0 -> [0]c0;
source1 -> [0]c1;
source2 -> [0]c2;

// Queue definition and connection to sink input 0.
out0 :: Queue(200) -> sink0;
out1 :: Queue(200) -> sink1;
out2 :: Queue(200) -> sink2;

// ARPQuerier definition. This wrap IP packets into Ethernet frames with given
//MAC destination previously asked.
arpq0 :: ARPQuerier($IP0, $MAC0);
arpq1 :: ARPQuerier($IP1, $MAC1);
arpq2 :: ARPQuerier($IP2, $MAC2);

// Deliver ARP responses to ARP queriers as well as Linux. Tee() is a packet
//multiplier and delive each copy in certain number of output ports.
// Aparentemente não há necessidade desses diversos classificadores e cópias de
//pacotes, pois tudo poderia entrar em um só ARPResponder com diferentes
//atributos.
t :: Tee(4);
c0[1] -> t;
c1[1] -> t;
c2[1] -> t;
t[0] -> Discard;
t[1] -> [1]arpq0;
t[2] -> [1]arpq1;
t[3] -> [1]arpq2;

// Connect ARP outputs to the interface queues.
arpq0 -> out0;
arpq1 -> out1;
arpq2 -> out2;

//IP packets input 0 are waiting...
Idle -> [0]arpq0;
Idle -> [0]arpq1;
Idle -> [0]arpq2;

// ARP Responder definitions. It going to answer ARP queriers with an IP-matched
//MAC address It could be more than one per MAC address. It's useful for network
//visibility by anothers and vice versa.
// Remember that the Querier needs incoming routes to and outgoing from this
//machine.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through hardware queues.
arpr0 :: ARPResponder($IP0 $MAC0, 192.168.251.0/24 $MAC0);
c0[0] -> arpr0 -> out0;

arpr1 :: ARPResponder($IP1 $MAC1, 172.16.30.0/23 $MAC1);
c1[0] -> arpr1 -> out1;

arpr2 :: ARPResponder($IP2 $MAC2, 172.16.30.0/23 $MAC2);
c2[0] -> arpr2 -> out2;

// Static IP table definition. It going to send matched packets to respective
//outputs:
// 0: packets for this machine.
// 1: packets for 192.168.251.
// 2: packets for 192.168.252.
// 3: packets for 172.16.30.
rt :: StaticIPLookup(192.168.251.1/32 0,
                    192.168.251.255/32 0,
                    192.168.251.0/32 0,
                    192.168.252.1/32 0,
                    192.168.252.255/32 0,
                    192.168.252.0/32 0,
                    172.16.30.162/32 0,
                    172.16.30.255/32 0,
                    172.16.30.0/32 0,
                    192.168.251.0/24 1,
                    192.168.252.0/24 2,
                    172.16.30.0/23 3
                    );

// Ethernet header unwrapping definition, followed for an IP header checking
//that drop any invalid packets, even those broadcats spreadings (when
//broadcasts are source address). Next, an IP classifier is defined and filter
//packets according to dst net and icmp packet. At least, they are shown in
//console and dropped.
ip ::   Strip(14)
     -> CheckIPHeader(INTERFACES 192.168.251.1/24 192.168.252.1/24 172.16.30.1/23)
     -> ICMPfilter :: IPClassifier('dst net 172.16.30.0/23' and 'icmp', -)
     -> Print('Droppado')
     -> Discard;

// Flow that doesn't match with filtering rules are delivered in output 1 and
//directed to static routing input.
ICMPfilter[1] -> [0]rt;

// Inserting annotations to IP frames to mark which interface they came from.
//It going to be useful after static routing, to find any packet that came and
//goes to same network.
// After annotations, frames are directed to unwrapping.
c0[2] -> Paint(3) -> ip;
c1[2] -> Paint(1) -> ip;
c2[2] -> Paint(2) -> ip;

// IP packets for this machine. What do you like to do? Me: Discard.
// ToHost expects ethernet packets, so cook up a fake header.
rt[0] -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> Discard;

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
rt[1] -> DropBroadcasts
      -> cp1 :: PaintTee(1)
      -> gio1 :: IPGWOptions(192.168.251.1)
      -> FixIPSrc(192.168.251.1)
      -> dt1 :: DecIPTTL
      -> fr1 :: IPFragmenter(1080) //o tamanho de 300 bytes tava dando problema na hora de usar o iperf
      -> Print ('P1')
      -> [0]arpq1;

rt[2] -> DropBroadcasts
      -> cp2 :: PaintTee(2)
      -> gio2 :: IPGWOptions(192.168.252.1)
      -> FixIPSrc(192.168.252.1)
      -> dt2 :: DecIPTTL
      -> fr2 :: IPFragmenter(1080) //o tamanho de 300 bytes tava dando problema na hora de usar o iperf
      -> Print ('P2')
      -> [0]arpq2;

rt[3] -> DropBroadcasts
      -> cp0 :: PaintTee(3)
      -> gio0 :: IPGWOptions(172.16.30.162)
      -> FixIPSrc(172.16.30.162) //ver como configura as anotações pra trocar os IPs
      -> dt0 :: DecIPTTL
      -> fr0 :: IPFragmenter(1080) //o tamanho de 300 bytes tava dando problema na hora de usar o iperf
      -> Print ('P0')
      -> [0]arpq0;

// DecIPTTL[1] emits packets with expired TTLs.
// Reply with ICMPs. Rate-limit them?
dt0[1] -> ICMPError(172.16.30.162, timeexceeded) -> [0]rt;
dt1[1] -> ICMPError(192.168.251.1, timeexceeded) -> [0]rt;
dt2[1] -> ICMPError(192.168.252.1, timeexceeded) -> [0]rt;

// Send back ICMP UNREACH/NEEDFRAG messages on big packets with DF set.
// This makes path mtu discovery work.
fr0[1] -> ICMPError(172.16.30.162, unreachable, needfrag) -> [0]rt;
fr1[1] -> ICMPError(192.168.251.1, unreachable, needfrag) -> [0]rt;
fr2[1] -> ICMPError(192.168.252.1, unreachable, needfrag) -> [0]rt;

// Send back ICMP Parameter Problem messages for badly formed
// IP options. Should set the code to point to the
// bad byte, but that's too hard.
gio0[1] -> ICMPError(172.16.30.162, parameterproblem) -> [0]rt;
gio1[1] -> ICMPError(192.168.251.1, parameterproblem) -> [0]rt;
gio2[1] -> ICMPError(192.168.252.1, parameterproblem) -> [0]rt;

// Send back an ICMP redirect if required.
cp0[1] -> ICMPError(172.16.30.162, redirect, host) -> [0]rt;
cp1[1] -> ICMPError(192.168.251.1, redirect, host) -> [0]rt;
cp2[1] -> ICMPError(192.168.252.1, redirect, host) -> [0]rt;

// Unknown ethernet type numbers.
c0[3] -> Print('unknown0') -> Discard;
c1[3] -> Print('unknown1') -> Discard;
c2[3] -> Print('unknown2') -> Discard;
