##Teste firewall
#Cliente 1 porta 80
ssh root@192.168.0.101 "date +%s >> siege_result.txt && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result.txt"

#Cliente 1 porta 8080
ssh root@192.168.0.101 "date +%s >> siege_result.txt && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:8080/index2.html && date +%s >> siege_result.txt"

#Bwm-NG porta 80
mkdir -p tnatlb/porta80 && bwm-ng -I vif1.0,vif7.0,vif7.1 -o csv -F tnatlb/porta80/bwmng.csv && scp root@192.168.0.101:/root/siege_result.txt tnatlb/porta80/

#Bwm-NG porta 8080
mkdir -p tnatlb/porta8080 && bwm-ng -I vif1.0,vif7.0,vif7.1 -o csv -F tnatlb/porta8080/bwmng.csv && scp root@192.168.0.101:/root/siege_result.txt tnatlb/porta8080/

##Teste balanceador de carga - Round Robin
#Cliente 1
ssh root@192.168.0.101 "date +%s >> siege_result.txt && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result.txt"

#Bwm-NG
mkdir -p tnatlb_rr/ && bwm-ng -I vif1.0,vif4.0,vif5.0,vif6.0 -o csv -F tnatlb_rr/bwmng.csv && scp root@192.168.0.101:/root/siege_result.txt tnatlb/

##Teste balanceador de carga - IP de origem
#Cliente 1
ssh root@192.168.0.101 "date +%s >> siege_result.txt && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result.txt && sleep 30 && date +%s >> siege_result2.txt && siege -b -t 15S -c 100 -lsiege_result2.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result2.txt"

#Cliente 2
ssh root@192.168.0.102 "date +%s >> siege_result.txt && sleep 15 && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result.txt && sleep 30 && date +%s >> siege_result2.txt && siege -b -t 15S -c 100 -lsiege_result2.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result2.txt"

#Cliente 3
ssh root@192.168.0.103 "date +%s >> siege_result.txt && sleep 30 && siege -b -t 15S -c 100 -lsiege_result.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result.txt && sleep 30 && date +%s >> siege_result2.txt && siege -b -t 15S -c 100 -lsiege_result2.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result2.txt"

#Bwm-NG
mkdir -p tnatlb_sip/101 && mkdir -p tnatlb_sip/102 && mkdir -p tnatlb_sip/103 && bwm-ng -I vif1.0,vif2.0,vif3.0,vif4.0,vif5.0,vif6.0 -o csv -F tnatlb_sip/bwmng.csv && scp root@192.168.0.101:/root/siege_resul*.txt tnatlb_sip/101/ && scp root@192.168.0.102:/root/siege_resul*.txt tnatlb_sip/102/ && scp root@192.168.0.103:/root/siege_resul*.txt tnatlb_sip/103/

##Teste balanceador de carga - Stress c/ Round Robin
