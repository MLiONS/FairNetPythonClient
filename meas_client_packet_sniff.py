# -*- coding: utf-8 -*-

# Imports
from scapy.all import *
from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite
from meas_client_global_const import s_th, dl_done, DEBUG, tout, app_to_ps_event_map
import threading
import meas_client_global_const

# Global variables and constants
plist = []


def mcl_join_sniffer():
    s_th.join()


def mcl_start_sniffer(debug,fp,app):
    output_data = "Packet Sniffer Started" + '\n'
    mcl_fwrite(debug,fp,output_data)
    print(output_data)
    #ps_event = app_to_ps_event_map[app]
    #print(ps_event)
    #pkts = sniff(iface="Qualcomm QCA9377 802.11ac Wireless Adapter #2",timeout=tout)
    #pkts = meas_client_global_const.sniff_pkts = sniff(iface="Qualcomm QCA9377 802.11ac Wireless Adapter #2",stop_filter=lambda x: dl_done.is_set())
    #pkts = meas_client_global_const.sniff_pkts = sniff(iface="Wi-Fi (en0)",stop_filter=lambda x: dl_done.is_set())
    pkts = meas_client_global_const.sniff_pkts = sniff(iface="en0", stop_filter=lambda x: dl_done.is_set())
    # pkts = meas_client_global_const.sniff_pkts = sniff(iface="lo0", stop_filter=lambda x: dl_done.is_set())
    # pkts = meas_client_global_const.sniff_pkts = sniff(iface="USB to Ethernet Adapter", stop_filter=lambda x: dl_done.is_set())
    # pkts = meas_client_global_const.sniff_pkts = sniff(stop_filter=lambda x: dl_done.is_set())
    #pkts = meas_client_global_const.sniff_pkts = sniff(iface="Qualcomm QCA9377 802.11ac Wireless Adapter #2",stop_filter=lambda x: ps_event.is_set())
    #pkts = meas_client_global_const.sniff_pkts = sniff(stop_filter=lambda x: ps_event.is_set())
    #output_data = str(pkts) + '\n'
    #mcl_fwrite(debug,fp,output_data)
    return pkts


def mcl_start_packet_sniffer_thread(debug,fp,app):
    #print("Sniffing")
    pkts = mcl_start_sniffer(debug,fp,app)
    plist.append(pkts)
    return pkts


def mcl_get_pkts():
    p = None
    cond = True
    while cond:
        for p in plist:
            if None == p:
                continue
            else:
                print(p)
                cond = False
                break;
    return p


def mcl_get_pkts_from_sniffer(debug,fp,ps,app):
    app_name = ""
    if None != app:
        app_name="_"+str(app)
    fname = "output_data/pkts"+str(app_name)+".pcap"
    print("Generating "+str(fname))
    print(meas_client_global_const.s_th)
    meas_client_global_const.s_th.join()
    #pkts = mcl_get_pkts()
    if None is not meas_client_global_const.sniff_pkts:
        wrpcap(fname, meas_client_global_const.sniff_pkts)
    mcl_fclose(fp)
    return meas_client_global_const.sniff_pkts


def mcl_sniff_packets(debug,app):
    fname = "output_data/pkt_sniffer_"+str(app)+".txt"
    fp = mcl_fopen(debug,fname,"w","DELETE")
    ps = threading.Thread(target=mcl_start_packet_sniffer_thread,args=(debug,fp,app,))
    meas_client_global_const.s_th = ps
    ps.start()
    return ps,fp


def mcl_packet_sniff_main():
    DEBUG = 1
    sth, fp = mcl_sniff_packets(DEBUG)
    abc = 1
    print(str(abc))
    pkts = mcl_get_pkts_from_sniffer(debug,fp)


if __name__=="__main__":
    mcl_packet_sniff_main()
