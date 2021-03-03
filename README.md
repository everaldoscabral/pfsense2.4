# pfsense2.4
Material para monitorar PfSense 2.4 no Zabbix.

Neste tutorial irei mostrar como monitorar o pfSense 2.4 + IPSec.

Este Template está associado ao Template default do Zabbix (Zabbix Agent), justamente para verificar a disponibilidade do Agent, já que ele é utilizado para realizar a coleta do itens. Por isto foi realizada a associação. Irei disponibilizar os 3 mas podem modificar a qualquer momento.

* Será necessário colocar o script pfsense_zbx.php em /root/scripts;
* Colocar os scripts zabbix-ipsec.py, check_ipsec.sh e check_ipsec_traffic.sh em /usr/local/bin;
* Agora no pfSense ir em Services --> Zabbix Agent 4.0 (estou utilizando essa versão do Agent) --> Clicar em Show Advanced Options e adicionar os user parameters que constam no documento para download. Depois basta salvar;
* Acessar SSH o Firewall e no modo Shell instalar: pkg install python27-2.7.18
* Realizar o download dos templates TEMPLATE-PFSENSE-2.4, TEMPLATE-PFSENSE-IPSEC-2.4 e TEMPLATE-ZABBIX-AGENT;
* Cadastrar o Host no Zabbix adicionando o IP dele na interfaces do agente;
* Criar as Expressões Regulares no Global ou remover do item caso deseje.

Pronto! Agora é verificar os itens coletados.

Link do blog: https://everaldoscabral.blogspot.com/2020/03/sobre-o-zabbix-monitoramento-de-pfsense.html?m=1
