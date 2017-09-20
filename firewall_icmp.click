// eth0, 08:00:27:43:9C:7F, 172.16.30.123
// eth1, 08:00:27:BF:8F:22, 192.168.251.1
// eth2, 08:00:27:C2:45:2B, 192.168.252.1

define($IP0 172.16.30.123);
define($IP1 192.168.251.1);
define($IP2 192.168.252.1);
define($MAC0 08:00:27:43:9C:7F);
define($MAC1 08:00:27:BF:8F:22);
define($MAC2 08:00:27:C2:45:2B);

//Os defines não funcionam aqui.
source0 :: FromDevice(eth0);
sink0   :: ToDevice(eth0);

source1 :: FromDevice(eth1);
sink1   :: ToDevice(eth1);

source2 :: FromDevice(eth2);
sink2   :: ToDevice(eth2);

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

source0 -> [0]c0;
source1 -> [0]c1;
source2 -> [0]c2;

out0 :: Queue(200) -> sink0;
out1 :: Queue(200) -> sink1;
out2 :: Queue(200) -> sink2;

arpq0 :: ARPQuerier($IP0, $MAC0);
arpq1 :: ARPQuerier($IP1, $MAC1);
arpq2 :: ARPQuerier($IP2, $MAC2);

// Deliver ARP responses to ARP queriers as well as Linux.
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

Idle -> [0]arpq0;
Idle -> [0]arpq1;
Idle -> [0]arpq2;

//Aê mano, eu respondo por esse ip aqui
arpr0 :: ARPResponder($IP0 $MAC0, 192.168.251.0/24 $MAC0); //não esquecer que a máquina externa precisa que a rota para o destino passe aqui.
c0[0] -> arpr0 -> out0;

//Oh mano, eu respondo por esse IP, mas se tu mandar pacotes dessa rede aqui eu tbm me viro.
arpr1 :: ARPResponder($IP1 $MAC1, 172.16.30.0/23 $MAC1);
c1[0] -> arpr1 -> out1;

//Oh mano, eu respondo por esse IP, mas se tu mandar pacotes dessa rede aqui eu tbm me viro.
arpr2 :: ARPResponder($IP2 $MAC2, 172.16.30.0/23 $MAC2);
c2[0] -> arpr2 -> out2;

// 0: packets for this machine.
// 1: packets for 192.168.251.
// 2: packets for 192.168.252.
// 3: packets for 172.16.30.
// All other packets are sent to output 3, with 172.16.30.123 as the gateway.
rt :: StaticIPLookup(192.168.251.1/32 0,
		    192.168.251.255/32 0,
		    192.168.251.0/32 0,
		    192.168.252.1/32 0,
		    192.168.252.255/32 0,
		    192.168.252.0/32 0,
        172.16.30.123/32 0,
		    172.16.30.255/32 0,
		    172.16.30.0/32 0,
		    192.168.251.0/24 1,
		    192.168.252.0/24 2,
        172.16.30.0/23 3);

// Retira o cabeçalho, e elimina broadcasts cujo destino não seja o
// próprio roteador, para não propagar infinitamente o broadcast.
ip ::   Strip(14)
     -> CheckIPHeader(INTERFACES 192.168.251.1/24 192.168.252.1/24 172.16.30.1/23)
     -> ICMPfilter :: IPClassifier('dst net 172.16.30.0/23' and 'icmp', -)
     -> Print('Droppado')
     -> Discard;

ICMPfilter[1] -> [0]rt;

c0[2] -> Paint(3) -> ip;
c1[2] -> Paint(1) -> ip;
c2[2] -> Paint(2) -> ip;

// IP packets for this machine.
// ToHost expects ethernet packets, so cook up a fake header.
rt[0] -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> Discard;
//rt[0] -> ICMPPingResponder() -> Print('Responder') -> EtherMirror() -> sink;

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
      -> gio0 :: IPGWOptions(172.16.30.123)
      -> FixIPSrc(172.16.30.123) //ver como configura as anotações pra trocar os IPs
      -> dt0 :: DecIPTTL
      -> fr0 :: IPFragmenter(1080) //o tamanho de 300 bytes tava dando problema na hora de usar o iperf
      -> Print ('P0')
      -> [0]arpq0;

// DecIPTTL[1] emits packets with expired TTLs.
// Reply with ICMPs. Rate-limit them?
dt0[1] -> ICMPError(172.16.30.123, timeexceeded) -> [0]rt;
dt1[1] -> ICMPError(192.168.251.1, timeexceeded) -> [0]rt;
dt2[1] -> ICMPError(192.168.252.1, timeexceeded) -> [0]rt;

// Send back ICMP UNREACH/NEEDFRAG messages on big packets with DF set.
// This makes path mtu discovery work.
fr0[1] -> ICMPError(172.16.30.123, unreachable, needfrag) -> [0]rt;
fr1[1] -> ICMPError(192.168.251.1, unreachable, needfrag) -> [0]rt;
fr2[1] -> ICMPError(192.168.252.1, unreachable, needfrag) -> [0]rt;

// Send back ICMP Parameter Problem messages for badly formed
// IP options. Should set the code to point to the
// bad byte, but that's too hard.
gio0[1] -> ICMPError(172.16.30.123, parameterproblem) -> [0]rt;
gio1[1] -> ICMPError(192.168.251.1, parameterproblem) -> [0]rt;
gio2[1] -> ICMPError(192.168.252.1, parameterproblem) -> [0]rt;

// Send back an ICMP redirect if required.
cp0[1] -> ICMPError(172.16.30.123, redirect, host) -> [0]rt;
cp1[1] -> ICMPError(192.168.251.1, redirect, host) -> [0]rt;
cp2[1] -> ICMPError(192.168.252.1, redirect, host) -> [0]rt;

// Unknown ethernet type numbers.
c0[3] -> Print(c30) -> Discard;
c1[3] -> Print(c31) -> Discard;
c2[3] -> Print(c32) -> Discard;
