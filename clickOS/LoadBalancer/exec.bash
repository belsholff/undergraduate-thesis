##Teste firewall
#Cliente 1 porta 80
ssh root@192.168.0.101 "date +%s >> siege_result80.txt && siege -b -t 15S -c 100  -lsiege_result80.txt http://192.0.2.61:80/index2.html && date +%s >> siege_result80.txt"

#Bwm-NG porta 80
bwm-ng -I vif1.0,vif7.0,vif7.1 -o csv -F bwmng80.csv

#Cliente 1 porta 8080
ssh root@192.168.0.101 "date +%s >> siege_result8080.txt && siege -b -t 15S -c 100 -lsiege_result8080.txt http://192.0.2.61:8080/index2.html && date +%s >> siege_result8080.txt"

#Bwm-NG porta 8080
bwm-ng -I vif1.0,vif7.0,vif7.1 -o csv -F bwmng8080.csv

##Teste balanceador de carga - Round Robin
#Cliente 1
ssh root@192.168.0.101 "date +%s >> siege_resultRR.txt && siege -b -t 15S -c 100 -lsiege_resultRR.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultRR.txt"

#Bwm-NG
bwm-ng -I vif1.0,vif4.0,vif5.0,vif6.0 -o csv -F bwmngRR.csv

##Teste balanceador de carga - IP de origem
#Cliente 1
ssh root@192.168.0.101 "date +%s >> siege_resultSIP.txt && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt && sleep 30 && date +%s >> siege_resultSIP.txt && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt"

#Cliente 2
ssh root@192.168.0.102 "date +%s >> siege_resultSIP.txt && sleep 15 && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt && sleep 30 && date +%s >> siege_resultSIP.txt && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt"

#Cliente 3
ssh root@192.168.0.103 "date +%s >> siege_resultSIP.txt && sleep 30 && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt && sleep 30 && date +%s >> siege_resultSIP.txt && siege -b -t 15S -c 100 -lsiege_resultSIP.txt http://192.0.2.61:80/index2.html && date +%s >> siege_resultSIP.txt"

#Bwm-NG
bwm-ng -I vif1.0,vif2.0,vif3.0,vif4.0,vif5.0,vif6.0 -o csv -F bwmngSIP.csv

##Teste balanceador de carga - Stress c/ Round Robin
#Round Robin
ssh root@192.168.0.101 "for i in `seq 1 10`; do (( y=$i*100 )); siege -b -t 60S -c $y -lsiege_resultTRR.txt http://192.0.2.61:80/index2.html; sleep 300; done"

#Endereço IP de origem
ssh root@192.168.0.101 "for i in `seq 1 10`; do (( y=$i*100 )); siege -b -t 60S -c $y -lsiege_result_TSIP.txt http://192.0.2.61:80/index2.html; sleep 300; done"

#Sem Balanceador
ssh root@192.168.0.101 "for i in `seq 1 10`; do (( y=$i*100 )); siege -b -t 60S -c $y -lsiege_result_TSBAL.txt http://192.0.2.X:80/index2.html; sleep 300; done"

#Sem ClickOS
ssh root@192.168.0.101 "for i in `seq 1 10`; do (( y=$i*100 )); siege -b -t 60S -c $y -lsiege_result_TSCLI.txt http://198.51.100.X:80/index2.html; sleep 300; done"


#Criação
xl create /caminho/para/config_vnf.cfg

#Implantação | nome = 'name' dentro de arquivo.cfg
cosmos start nome /caminho/para/codigo_vnf.click

#Deleção | nome = 'name' dentro de arquivo.cfg
xl destroy nome

#Visualização de dados simples ou detalhada
xl list #ou
xentop

#Uso de manipuladores de elementos | nome = ...
cosmos read|write nome ident_elemento manipulador
#De acordo com o manipulador entre leitura e escrita

#Gerando para tela
clicky codigo_vnf.click

#Gerando para arquivo
clicky --pdf=/caminho/grafico_vnf.pdf codigo_vnf.click
