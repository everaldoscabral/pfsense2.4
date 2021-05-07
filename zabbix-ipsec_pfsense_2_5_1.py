#!/usr/local/bin/python3.7

import itertools
import re
import sys
import xml.etree.cElementTree as ET

IPSEC_CONF = '/var/etc/ipsec/swanctl.conf'
PFSENSE_CONF = '/conf/config.xml'
rtt_time_warn = 200
rtt_time_error = 300

#Parse the XML
tree = ET.parse(PFSENSE_CONF)
root = tree.getroot()

#Function to find phase description by ikeid
def findDescr(remoteid,ikeid):

        #Check if the parameter was sent
        if not remoteid:
                return "Not found"

        #create search string. We use the "..." after the search to return the parent element of the current element.
        #The reason for that is the remoteid is a sub element of phase2 element 
        search = "./ipsec/phase2/remoteid/[address='" + remoteid + "']..."

        for tunnel in root.findall(search):
                descr = tunnel.find('descr').text

                #If we have only one result, we are talking about the correct tunnel
                if len(root.findall(search)) == 1:
                        return descr

                #otherwise, if we have more than 1, we have to confirm the remoteid and the ikeid 
                #Case the ikeIds are the same, we got it. Case not, we pass and wait for next interation
                else:
                        #Get the ikeid of this element
                        ikeidElement = tunnel.find('ikeid').text
                        if ikeidElement == ikeid:
                                return descr

        return "Not found"

#Function to set correct format on ikeId. Recives conIDXXX, return ID
def formatIkeId(ikeid):
    
    #Convert list  into a string
    ikeid = ikeid[0]

    #If ikeid has 8 or more positions, get the position 3 and 4
    if len(ikeid) >= 8:
        ikeid = ikeid[3] + ikeid[4]
    else:
        #Else, get only the position 3. That is because some ikeids are small
        ikeid = ikeid[3]
    #print "The correct ike id is ", ikeid
    return ikeid

def parseConf():
    reg_conn = re.compile('^\s*con[0-9]{4,6}')
    reg_left = re.compile('.*local_addrs =(.*).*')
    reg_right = re.compile('.*remote_addrs =(.*).*')
    reg_rightsubnet = re.compile('.*remote_ts =(.*).*')
    data = {}
    with open(IPSEC_CONF, 'r') as f:
        soubor = f.read()
        groups = re.findall('(^\s*con[0-9]+.*?)(?=^\s*esp_proposals|\Z)', soubor, flags=re.DOTALL|re.MULTILINE)
        for g in groups:
            conn_tmp = list()
            m = re.search(reg_conn, g)
            m = m.group(0)
            m = m.lstrip('\t')
            m = m.replace('\n\t','')
            if m:
                conn_tmp.append(m)
            left_tmp = list()
            m1 = re.search(reg_left, g)
            m1 = m1.group(0)
            m1 = m1.strip('\t\tlocal_addrs =')
            if m1:
                left_tmp.append(m1)
            right_tmp = list()
            m2 = re.search(reg_right, g)
            m2 = m2.group(0)
            m2 = m2.strip('\t\tremote_addrs =')
            if m2:
                right_tmp.append(m2)
            descr = "Not found"
            if conn_tmp and left_tmp and right_tmp:
                    data[conn_tmp[0]] = [left_tmp[0], right_tmp[0], descr]
        return data

def getTemplate():
    template = """
        {{ "{{#TUNNEL}}":"{0}","{{#TARGETIP}}":"{1}","{{#SOURCEIP}}":"{2}","{{#DESCRIPTION}}":"{3}" }}"""

    return template

def getPayload():
    final_conf = """{{
    "data":[{0}
    ]
}}"""

    conf = ''
    data = parseConf().items()
    for key,value in data:
        tmp_conf = getTemplate().format(
            key,
            value[1],
            value[0],
            value[2],
            rtt_time_warn,
            rtt_time_error
        )
        if len(data) > 1:
            conf += '%s,' % (tmp_conf)
        else:
            conf = tmp_conf
    if conf[-1] == ',':
        conf=conf[:-1]
    return final_conf.format(conf)

if __name__ == "__main__":
    ret = getPayload()
    sys.exit(ret)
