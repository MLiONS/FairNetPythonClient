# -*- coding : utf-8 -*-

from scapy.all import *

def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

sniff(iface='Qualcomm QCA9377 802.11ac Wireless Adapter #2', prn=http_header)
