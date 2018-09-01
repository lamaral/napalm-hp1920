import re


def normalize_port_name(self, res_port):
    """ Convert Short HP interface names to long (ex: BAGG519 --> Bridge-Aggregation 519)"""
    if re.match('^BAGG\d+',res_port):
        # format port BAGG519 --> Bridge-Aggregation 519
        agg_port_name = res_port.replace('BAGG','Bridge-Aggregation ')
        return agg_port_name
    elif re.match('^Bridge-Aggregation\d*',res_port):
        agg_port_name = res_port
        return agg_port_name
    elif re.match('^XGE\d.*',res_port):
        # format port XGE1/2/0/7 --> Ten-GigabitEthernet 1/2/0/7
        port_name = res_port.replace('XGE','Ten-GigabitEthernet ')
        # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
        return port_name
    elif re.match('^GE\d.*',res_port):
        # format port GE1/5/0/19 --> GigabitEthernet 1/5/0/19
        port_name = res_port.replace('GE','GigabitEthernet ')
        # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
        return port_name
    elif re.match('^Vlan\d+',res_port):
        # format port Vlan4003 --> Vlan-interface4003
        port_name = res_port.replace('Vlan','Vlan-interface')
        # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
        return port_name
    else:
        return res_port 
        # print('\x1b[1;31;40m' + " --- Unknown Port Name: {} --- ".format(res_port)+'\x1b[0m')