// Network in vnf.cfg:
// vif         = ['ip=10.0.0.1,mac=00:19:85:11:00:54,bridge=yourBridge',
//                'ip=anotherIP,mac=anotherMAC,bridge=anotherBridge']
// If you'll use this, please change vnf.cfg with network information, change
//AdressInfo with networks configured, duplicate this structure for new networks,
//and then, make an analysis of witch elements are needed. After all, start
//development of your VNF.

//          name             ip           ipnet         mac (def em vnf.cfg)
AddressInfo(net0        10.0.0.1       10.0.0.0/8     00:19:85:11:00:54, ...);

entrada :: FromDevice(0); //0->1ª vif declarada no vnf.cfg
saida :: ToDevice(0);

classificador :: Classifier(12/0806 20/0001, // saida 0. pacotes consulta ARP
                            12/0806 20/0002, // saida 1. pacotes resposta ARP
                            12/0800,         // saida 2. pacotes IP
                            -);              // saida 3. outros

// arpQ :: ARPQuerier(net0:ip, net0:mac); //ou
arpQ :: ARPQuerier(net0);

// arpR :: ARPResponder(net0:ip, net0:mac); //ou
arpR :: ARPResponder(net0);

fila :: Queue(200);

entrada -> classificador;
fila -> saida;
classificador[0] -> arpR -> fila; //ou assim: arpR[0], [0]arpR, [0]arpR[0]
classificador[1] -> [1]arpQ;
Idle -> [0]arpQ;
arpQ -> fila;

classificador[2] -> /SEUS ELEMENTOS/
                 -> /PARA MANIPULAR PACOTES IP/
                 -> /OPERAM NO FLUXO A PARTIR DAQUI/
                 -> arpQ; //em uma linha também funciona (veja linha 27)

classificador[3] -> Discard;
