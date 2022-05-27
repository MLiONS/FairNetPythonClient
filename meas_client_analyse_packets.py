# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.inet6 import IPv6

from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite
from meas_client_global_const import *

INVALID = 'XX'
PROT_TCP = 6
PROT_UDP = 17
MAX_NUM_PKTS = 15000
MIN_NUM_PKS = 100
MAX_SLOT_SIZE = 2.75# 0.75 corresponds to 0.75s * 3 Mbps = 2.25 Mb data
MAX_DIS_TIME = 2
PLT_ON: int = 0


# Utility Functions


def mcl_count_num_pkts(pkts):
    pcount = 0
    for pkt in pkts:
        pcount += 1
    return pcount


def mcl_get_hostname():
    import socket
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    return ip_addr


def mcl_get_packet_seq(pkt, prot):
    if "TCP" == prot:
        seq = pkt[TCP].seq
    else:
        seq = INVALID
    return seq


def mcl_get_packet_protocol(pkt):
    if PROT_UDP == pkt[IP].proto:
        prot = 'UDP'
    elif PROT_TCP == pkt[IP].proto:
        prot = 'TCP'
    else:
        prot = INVALID
    return prot


def mcl_get_tr_payload_len(pkt, prot):
    if "TCP" == prot:
        return len(pkt[TCP].payload)
    if "UDP" == prot:
        return len(pkt[IP].payload)
    else:
        return INVALID


def mcl_delete_file(fname):
    import os
    if os.path.exists(fname):
        os.remove(fname)


def mcl_sniffer_deinit():
    mcl_delete_file("output_data/pdata.txt")
    mcl_delete_file("output_data/sniff_pkt.txt")
    mcl_delete_file("output_data/pth_88888888.txt")


# Process sniffed packets
def mcl_process_packets_sd(pkts):
    import os
    from struct import unpack
    olist = []
    port_list = []
    file_list = []
    idx = 1
    rlen = 0
    for pkt in pkts:
        prot = mcl_get_packet_protocol(pkt)
        sd_port = str(pkt[prot].sport) + str(pkt[prot].dport)
        seq = mcl_get_packet_seq(pkt, prot)
        # rlen = len(" ".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")))
        rlen = mcl_get_tr_payload_len(pkt, prot)
        if 0 == rlen:
            continue
        # pkt_info = pkt_struct(pkt.seq_num,pkt.d_size,pkt.time)
        if sd_port not in port_list:
            pl = []
            pl.append((pkt.time, seq, rlen))
            olist.append((sd_port, pl))
            port_list.append(sd_port)
            fname = "output_data/" + str(pkt[prot].sport) + "_" + str(pkt[prot].dport) + "_" + "pkts.txt"
            # print(fname)
            mcl_delete_file(fname)
            f = open(fname, 'a')
            output_data = str("Time") + ' ' + str("SN") + ' ' + str("Length") + ' ' + '\n'
            f.write(output_data)

            file_list.append((sd_port, f))
            idx += 1
            # f.close()
            # print("Idx = ",idx, "SP = ",pkt.s_port)
            if MAX_NUM_FILE < idx:
                print("Too many file open")
                return None
        else:
            for data in olist:
                if data[0] == sd_port:  # Comparing source+dest sport
                    data[1].append((pkt.time, seq, pkt[IP].len))
                    # data.fname.append(pkt)
        for file in file_list:
            if file[0] == sd_port:
                f = file[1]
        output_data = str(pkt.time) + ' ' + str(seq) + ' ' + str(rlen) + '\n'
        f.write(output_data)
        # f.close()
    for file in file_list:
        file[1].close()
    return olist


def mcl_init_app_to_pkt_dict(app_to_pkts):
    for app in app_list:
        app_to_pkts[app] = []
    return app_to_pkts


def mcl_get_ip_enum(pkt):
    if IP in pkt:
        return IP
    if IPv6 in pkt:
        return IPv6
    else:
        return None


def mcl_filter_packets(fp, pkts, map, host, app):
    from socket import gethostbyname
    from socket import gethostname
    from socket import gethostbyaddr
    # app_to_pkts = {}
    plist = []
    c = 0
    num_pkts = 0
    # app_to_pkts = mcl_init_app_to_pkt_dict(app_to_pkts)
    if None == host:
        host = mcl_get_hostname()
    print("Sniffing " + str(host) + '\n')
    # print(map)
    for pkt in pkts:
        seq = INVALID
        # print(pkt)
        if IP not in pkt:  # and IPv6 not in pkt:
            # print("IP not present")
            continue
        ip = mcl_get_ip_enum(pkt)
        # print("IP: "+str(ip))

        if IPv6 in pkt:
            host = socket.getaddrinfo('DESKTOP-D1BKSO3', None, socket.AF_INET6)[1][4][0]
            print(host)

        if True:
            # host == str(pkt[ip].dst):
            # print(str(str(pkt[ip].dst)))
            if 0 == c:
                ts = pkt.time
                c = 1
            prot = mcl_get_packet_protocol(pkt)
            if INVALID == prot:
                # print("No protocol")
                continue
            rlen = mcl_get_tr_payload_len(pkt, prot)
            if 0 == rlen:
                # print("No data")
                continue
            seq = mcl_get_packet_seq(pkt, prot)
            tos = INVALID
            apptype = app.split("_")[1]
            # print("Entered wrongly Outside")
            # print("APPTYPE: "+str(apptype))
            if int(apptype) != 3 and int(apptype) != 4:
                # print("Entered wrongly")
                if pkt[prot].dport not in map:
                    # print("Dropping:"+str(pkt[prot].dport)+'\n')
                    continue
                if map[pkt[prot].dport] != app:
                    # print(str(map[pkt[prot].dport])+" : "+str(app))
                    # print("Dropping due to app :"+str(pkt[prot].dport)+ str(map[pkt[prot].dport])+'\n')
                    continue
            # app = map[pkt[prot].dport]
            # app_to_pkts[app].append(pkt)
            plist.append(pkt)
            # output_data = str(pkt[prot].sport) + ' ' + str(seq) + ' ' + str(pkt[IP].len) + ' ' + str(pkt[IP].src) + ' ' + str(prot) + ' ' + str(pkt[prot].dport) + '\n'
            # output_data = str(pkt.time) + ' : ' + str(pkt[IP].src) + ' : ' + str(pkt[prot].sport) + ' : ' + str(pkt[prot].dport) + ' : ' + str(seq) + ' : ' + str(pkt[IP].len) + '\n'
            # output_data = str(pkt.time) + ' : ' + str(pkt[IP].src) + ' : ' + str(pkt[IP].dst) + ' : ' + str(pkt[IP].len) + ' : ' + str(pkt[IP].proto) + '\n'
            # mcl_fwrite(debug,fp,output_data)
            te = pkt.time
            num_pkts += 1
            if MAX_NUM_PKTS < num_pkts:
                break
    tdiff = te - ts
    output_data = "TDiff = " + str(tdiff) + "NumPkts = " + str(num_pkts) + '\n'
    print(output_data)
    mcl_fwrite(debug, fp, output_data)
    return plist
    # return app_to_pkts


def mcl_det_sn_incon(plist):
    pkt = []
    d_pkt = 0
    for packet in plist:
        if packet in pkt:
            d_pkt += 1
            continue
        else:
            pkt.append(packet)
    return d_pkt, pkt


def mcl_extract_packet_info(pkts):
    olist = []
    for pkt in pkts:
        prot = mcl_get_packet_protocol(pkt)
        seq = mcl_get_packet_seq(pkt, prot)
        rlen = mcl_get_tr_payload_len(pkt, prot)
        olist.append((pkt.time, seq, rlen))
    return olist


def mcl_extract_n_sanitize_packet_info(app_pkts, app, app_pkt_info):
    # app_pkt_info = {}
    # for app in app_list:
    pkt_list = mcl_extract_packet_info(app_pkts)
    if DEBUG:
        fname = "output_data/perf_" + str(app) + "_ex.txt"
        fapp = mcl_fopen(DEBUG, fname, "a", "DELETE")
        output_data = str("Time") + ' ' + str("SN") + ' ' + str("Length") + '\n'
        mcl_fwrite(DEBUG, fapp, output_data)
        for pkt in pkt_list:
            output_data = str(pkt[0]) + ' ' + str(pkt[1]) + ' ' + str(pkt[2]) + '\n'
            mcl_fwrite(DEBUG, fapp, output_data)
        mcl_fclose(fapp)
    d_pkts, cplist = mcl_det_sn_incon(pkt_list)
    if DEBUG:
        fname = "output_data/perf_" + str(app) + "_sn.txt"
        fapp = mcl_fopen(DEBUG, fname, "a", "DELETE")
        output_data = str(d_pkts) + '\n'
        mcl_fwrite(DEBUG, fapp, output_data)
        output_data = str("Time") + ' ' + str("SN") + ' ' + str("Length") + '\n'
        mcl_fwrite(DEBUG, fapp, output_data)
        for pkt in cplist:
            output_data = str(pkt[0]) + ' ' + str(pkt[1]) + ' ' + str(pkt[2]) + '\n'
            mcl_fwrite(DEBUG, fapp, output_data)
        mcl_fclose(fapp)
    app_pkt_info[app] = cplist
    return app_pkt_info


def mcl_process_sniffed_pkts(fp, plist, map, host, app, app_pkt_info):
    app_to_pkts = mcl_filter_packets(fp, plist, map, host, app)
    # print("app_to_pkts : ")
    # print(app_to_pkts)
    if DEBUG:
        # for app in app_list:
        # for pkt in app_to_pkts[app]:
        for pkt in app_to_pkts:
            output_data = str(pkt) + '\n'
            mcl_fwrite(debug, fp, output_data)
    app_pkt_info = mcl_extract_n_sanitize_packet_info(app_to_pkts, app, app_pkt_info)
    return app_pkt_info


# Calculate performance parameters


def mcl_get_time_correction(t):
    import decimal as decimal
    ct = t
    dt = decimal.Decimal(str(t))
    d = abs(dt.as_tuple().exponent)
    if d < 6:
        ct = ct + 0.000001
    return ct


def mcl_calc_app_sliding_time_window_avg_throughput(t_del, fp, p):
    l = len(p)
    print(len(p))
    t_tot = 0
    cd = 0
    pt = 0
    pcount = 0
    pth = []
    pindex = []
    for ls in range(0, l):
        for i in range(ls, l):
            ct = mcl_get_time_correction(p[i][0])
            if 0 == pt:
                cd = p[i][2]
                pt = ct
                continue
            tdiff = ct - pt
            t_tot = t_tot + tdiff
            pt = ct
            if t_tot < t_del:
                cd += p[i][2]
                continue
            th = cd / (t_tot * 1000)
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            break;
        t_tot = 0
        cd = 0
        pt = 0

    return pindex, pth


def mcl_calc_app_time_window_avg_throughput(t_del, fp, plist):
    import decimal as decimal
    l = len(plist)
    print("tdel =" + str(t_del) + '\n')
    t_tot = 0
    throughput = 0
    cd = 0
    pt = 0
    pcount = 0
    pth = []
    pindex = []
    pidx = 0
    prange_l = 0
    prange_h = 100000
    for p in plist:
        pidx += 1
        # if pidx < prange_l:
        #    continue
        # if pidx > prange_h:
        #    break;
        ct = p[0]
        dt = decimal.Decimal(str(ct))
        d = abs(dt.as_tuple().exponent)
        if d < 6:
            ct = ct + 0.000001
        if 0 == pt:
            pt = ct
            cd = p[2]
            continue
        tdiff = ct - pt
        t_tot = t_tot + tdiff
        pt = ct
        if t_tot < t_del:
            cd += p[2]
            continue
        th = cd / (t_tot * 1000)
        # print(str(od) + " " + str(pt) + " " + str(pd)+ " " + str(tdiff) + "TH="+ str(th) + '\n')
        pcount += 1
        pth.append(th)
        pindex.append(pcount)
        output_data = str(pt) + ' ' + str(ct) + ' ' + str(cd) + ' ' + str(tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        t_tot = 0
        pt = 0
        cd = 0
        if pcount > 400:
            break
    return pindex, pth


def mcl_calc_app_inst_throughput(fp, plist):
    import decimal as decimal
    l = len(plist)
    throughput = 0
    cd = 0
    pt = 0
    pcount = 0
    pth = []
    pindex = []
    for p in plist:
        cd = p[2]
        ct = p[0]
        dt = decimal.Decimal(str(ct))
        d = abs(dt.as_tuple().exponent)
        if d < 6:
            ct = ct + 0.000001
        if 0 == pt:
            pt = ct
            continue
        tdiff = ct - pt
        # if tdiff < 0.1:
        #    continue
        th = cd / (tdiff * 1000)
        # print(str(od) + " " + str(pt) + " " + str(pd)+ " " + str(tdiff) + "TH="+ str(th) + '\n')
        pcount += 1
        pth.append(th)
        pindex.append(pcount)
        output_data = str(pt) + ' ' + str(ct) + ' ' + str(cd) + ' ' + str(tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        pt = ct
    return pindex, pth


def mcl_calc_app_runavg_throughput(fp, plist):
    import decimal as decimal
    l = len(plist)
    throughput = 0
    rt = 0
    pd = 0
    ot = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    pct = 0
    print("Plist : " + str(plist))
    for p in plist:
        if p[2] < 5:
            continue
        output_data = str(p[0]) + ' ' + str(p[1]) + ' ' + str(p[2]) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        # if pct < 600:
        #    pct += 1
        #    continue
        ot = p[0]
        dt = decimal.Decimal(str(p[0]))
        d = abs(dt.as_tuple().exponent)
        if d < 6:
            ot = ot + 0.000001
        print(ot)
        x = input()
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ot
            # pd = p[2]
            pcount += 1
            pth.append(th)
            # pindex.append(pcount)
            pindex.append(tdiff)
            output_data = str(pcount) + ' ' + str(p[2]) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ot) + ' ' + str(
                tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        tdiff = ot - rt
        if 1 == pcount:
            ot = rt
            # pd = pd + p[2]
            pcount += 1
            pth.append(th)
            # pindex.append(pcount)
            pindex.append(tdiff)
            continue
        # if tdiff < 0.01:
        #    print(tdiff)
        #    pd = pd + p[2]
        #    continue
        # if tdiff > 0.1:
        #    tdiff = tdiff - 0.1
        pd = pd + p[2] * 8
        th = pd / tdiff
        # print(str(od) + " " + str(pt) + " " + str(pd)+ " " + str(tdiff) + "TH="+ str(th) + '\n')
        pcount += 1
        pth.append(th)
        # pindex.append(pcount)
        pindex.append(tdiff / 10)
        output_data = str(pcount) + ' ' + str(p[2]) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ot) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(ot) + " LastT = " + str(
        rt) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    print(output_data)
    return pindex, pth


def mcl_calc_app_speed(plist):
    i = 0
    tspeed = 0
    num_sample = len(plist) - 4
    for p in plist:
        if i < 4:
            i += 1
            continue
        tspeed += p
        i += 1
    # print("tspeed = "+str(tspeed))
    # print("Num sample = "+str(num_sample))
    speed = tspeed / (len(plist) - 4)
    print("Speed = " + str(speed))


def mcl_calc_app_speed_list(fp, plist):
    pcount = 0
    pth = []
    pindex = []
    pd = 0
    tdiff = 0
    ptdiff = 0
    ppd = 0
    for p in plist:
        ptdiff = tdiff
        ppd = pd
        speed = 0
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        tdiff += float(p.dtime)
        pd += p.dlen
        if 0 != tdiff:
            speed = (pd * 1000 * 8) / (tdiff * 1000)
        if speed < 1000000:
            tdiff = ptdiff
            pd = ppd
            continue
        pcount += 1
        pth.append(speed)
        pindex.append(pcount)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(tdiff) + ' ' + str(speed) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


# TODO
def mcl_calc_app_time_windowed_athroughput(fp, plist, stime, etime, max_slot_time):
    from datetime import datetime
    lplist = len(plist)
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    cpindex = 0
    rtime = 0
    # print("Data size = "+str(len(plist)))
    tsdiff = 0
    if "" == max_slot_time:
        max_slot_time = MAX_SLOT_SIZE
    for p in plist:
        # output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        # mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cpindex = ct#.timestamp()
        ct = cpindex
        # print("Current time : "+str(cpindex))
        #if cpindex < stime or cpindex > etime:
            # print("Out of range " + str(int(cpindex)) + ":" + str(int(cpindex)-int(stime)) + ":" + str(int(etime)-int(cpindex)))
            #continue
        if 0 == rt:
            # output_data = "Reference updated \n"
            # mcl_fwrite(DEBUG, fp, output_data)
            # print("First cpindex = " + str(cpindex))
            rt = cpindex
            pcount += 1
            pth.append(th)
            # pindex.append(pcount)
            pindex.append(0)
            rtime = cpindex
            # print("Reference Time =" + str(rtime))
            # output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
            #              str(tdiff) + ' ' + str(th) + '\n'
            # mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            pd = pd + p.dlen
            continue
        pt = cpindex
        tdiff = ct - rt
        # tdiff = tdiff.microseconds/1000
        # tdiff = tdiff.total_seconds()
        # print("TDiff = "+str(tdiff))
        # +Slot logic
        if tdiff < max_slot_time:
            pd = pd + p.dlen
            continue
        if 0 == max_slot_time:
            pd = pd + p.dlen
            th = (pd * 1000 * 8) / (tdiff * 1000)
        else:
            th = (pd * 1000 * 8) / (tdiff * 1000)
            pd = 0
            rt = ct
        # -Slot logic
        pcount += 1
        # print("Pcount = "+str(pcount))
        pth.append(th)
        # pindex.append(pcount)
        tsdiff = cpindex - rtime
        # print("TDiff = " + str(tsdiff))
        pindex.append(tsdiff)
        # output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
        #    tdiff) + ' ' + str(th) + '\n'
        # mcl_fwrite(DEBUG, fp, output_data)
    if pd is not 0:
        th = (pd * 1000 * 8 * 1000) / (tdiff * 1000)
        # print("Single tdiff = " + str(tdiff) + "Single th = " + str(th))
        pcount += 1
        # pth.append(th)
        # pindex.append(pcount)
        tsdiff = cpindex - rtime
        # pindex.append(cpindex)
    # print("Last cpindex = "+str(cpindex))
    # print("TDiff = " + str(tsdiff))
    # print("pcout = "+str(pcount))
    #output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
    #    ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    #print(output_data)
    #output_data = str(pth)
    #mcl_fwrite(DEBUG, fp, output_data)
    # output_data = str(pindex)
    # mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_app_data_windowed_athroughput(fp, plist, stime, etime, max_slot_time):
    from datetime import datetime
    lplist = len(plist)
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    cpindex = 0
    rtime = 0
    seg_size = 625000
    # print("Data size = "+str(len(plist)))
    tsdiff = 0
    if "" == max_slot_time:
        max_slot_time = MAX_SLOT_SIZE
    for p in plist:
        # output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        # mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cpindex = ct#.timestamp()
        ct = cpindex
        # print("Current time : "+str(cpindex))
        #if cpindex < stime or cpindex > etime:
            # print("Out of range " + str(int(cpindex)) + ":" + str(int(cpindex)-int(stime)) + ":" + str(int(etime)-int(cpindex)))
        #    continue
        if 0 == rt:
            # output_data = "Reference updated \n"
            # mcl_fwrite(DEBUG, fp, output_data)
            # print("First cpindex = " + str(cpindex))
            rt = cpindex
            pcount += 1
            pth.append(th)
            # pindex.append(pcount)
            pindex.append(0)
            rtime = cpindex
            # print("Reference Time =" + str(rtime))
            # output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
            #              str(tdiff) + ' ' + str(th) + '\n'
            # mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            pd = pd + p.dlen
            continue
        pt = cpindex
        tdiff = ct - rt
        # tdiff = tdiff.microseconds/1000
        # tdiff = tdiff.total_seconds()
        # print("TDiff = "+str(tdiff))
        # +Slot logic
        # if tdiff < max_slot_time:
        if pd < seg_size:
            pd = pd + p.dlen
            continue
        if 0 == max_slot_time:
            pd = pd + p.dlen
            th = (pd * 1000 * 8) / (tdiff * 1000)
        else:
            th = (pd * 1000 * 8) / (tdiff * 1000)
            pd = 0
            rt = ct
        # -Slot logic
        pcount += 1
        # print("Pcount = "+str(pcount))
        pth.append(th)
        # pindex.append(pcount)
        tsdiff = cpindex - rtime
        # print("TDiff = " + str(tsdiff))
        pindex.append(tsdiff)
        # output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
        #    tdiff) + ' ' + str(th) + '\n'
        # mcl_fwrite(DEBUG, fp, output_data)
    if pd is not 0:
        th = (pd * 1000 * 8 * 1000) / (tdiff * 1000)
        # print("Single tdiff = " + str(tdiff) + "Single th = " + str(th))
        pcount += 1
        # pth.append(th)
        # pindex.append(pcount)
        tsdiff = cpindex - rtime
        # pindex.append(cpindex)
    # print("Last cpindex = "+str(cpindex))
    # print("TDiff = " + str(tsdiff))
    # print("pcout = "+str(pcount))
    #output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
    #    ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    #print(output_data)
    #output_data = str(pth)
    #mcl_fwrite(DEBUG, fp, output_data)
    # output_data = str(pindex)
    # mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_app_athroughput(fp, plist):
    print("mcl_calc_app_athroughput")
    from datetime import datetime
    lplist = len(plist)
    # print("In app throughput " + str(lplist))
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    for p in plist:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        # print("CT : " + str(ct))
        # x = input()
        # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cpindex = ct#.timestamp()
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            # pindex.append(cpindex)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            pd = pd + p.dlen
            continue
        tdiff = ct - rt
        # tdiff = tdiff.total_seconds()
        if tdiff < 0.01:
            continue
        pd = pd + p.dlen
        th = (pd * 1000 * 8) / (tdiff * 1000)
        pcount += 1
        pt = ct
        pth.append(th)
        # print("TH = " + str(th))
        # x = input()
        pindex.append(pcount)
        # pindex.append(cpindex)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    # print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_per_app_data(fp, plist):
    # print("mcl_calc_per_app_data")
    from datetime import datetime
    lplist = len(plist)
    # print("In app throughput " + str(lplist))
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    for p in plist:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        if type(ct) is float:
            cpindex = ct
        else:
            ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
            cpindex = ct.timestamp()
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pcount += 1
            pth.append(p.dlen)
            # pindex.append(pcount)
            pindex.append(cpindex)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            continue
        pcount += 1
        pt = ct
        pth.append(p.dlen)
        # pindex.append(pcount)
        pindex.append(cpindex)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    # output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
    #   ct) + '\n'
    # print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_per_seg_app_data(fp, plist):
    # print("mcl_calc_per_app_data")
    from datetime import datetime
    lplist = len(plist)
    # print("In app throughput " + str(lplist))
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    seg_data = 0
    th = 0
    pdlen = 0
    pscount = 0
    psscount = 0;
    for p in plist:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        if type(ct) is float:
            cpindex = ct
        else:
            cpindex = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
            cpindex = cpindex.timestamp()
        ct = cpindex
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pt = ct
            pdlen = p.dlen
            seg_data = 0
            # pcount += 1
            # pth.append(0)
            # pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if ct == pt:
            continue
        # print("Dlen = "+str(p.dlen))
        if MAX_SEG_DATA >= seg_data:
        # if pdlen == p.dlen:
            # print(str(p.dlen))
            # print(str(pscount) + ":" + str(p.dlen) + " : " + str(ct) + " : " + str(pt))
            seg_data += p.dlen
            pt = ct
            pscount += 1
            continue
        # if 10 > pscount:
        #    psscount += 1
            # print(str(pscount) + ":" + str(pdlen) + " : " + str(ct) + " : " + str(pt))
        # x = input()
        tdiff = ct - rt
        # print("Ctime = "+str(ct) + ":" + "Ptime = " + str(pt))
        # tdiff = tdiff.total_seconds()
        th = (seg_data * 1000 * 8) / (tdiff * 1000)
        print("SEG_DATA = "+str(seg_data) + " : " + str(tdiff) + ":" + str(th))
        # print(str(p.dlen) + ":" + str(seg_data) + ":" + str(tdiff) + " : " + str(th))
        pth.append(th)
        pindex.append(pcount)
        pcount += 1
        # seg_data = 0
        rt = ct
        seg_data = p.dlen
        pdlen = p.dlen
        pscount = 0
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    # output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
    #   ct) + '\n'
    # print(output_data)
    # print("Short bursts = " + str(psscount))
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_per_app_data_tdiff(fp, plist):
    print("mcl_calc_per_app_data_tdiff")
    from datetime import datetime
    lplist = len(plist)
    # print("In app throughput " + str(lplist))
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    for p in plist:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cpindex = ct.timestamp()
        ct = cpindex
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pt = ct
            pcount += 1
            pth.append(0)
            # pindex.append(pcount)
            pindex.append(cpindex)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            continue
        pcount += 1
        pth.append((ct-pt)*1000)
        # pindex.append(pcount)
        pindex.append(cpindex)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        pt = ct
    # output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
    #   ct) + '\n'
    # print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_get_all_bsizes(data):
    import re
    rtext = 'BURST-END:([0-9][0-9][0-9][0-9]))'
    res = re.findall(rtext, data, re.IGNORECASE)
    return res


def mcl_get_app_burst_time_size_list(fp, slist, tlist):
    rlist = []
    for p in tlist:
        dtime = p.dtime
        nbursts = int(p.dlen)
        for i in range(0, nbursts):
            dsize = slist.pop(0)
            pa = dinfo_struct(dtime, dsize)
            rlist.append(pa)
            output_data = str(pa) + '\n'
            fp.write(output_data)
    return rlist


def mcl_calc_app_runavg_bthroughput(fp, bts_list):
    import sys
    from datetime import datetime
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    lt = 0
    tdiff = 0
    tdiff_off = 0
    pcount = 0
    pth = []
    pindex = []
    th = 0
    rcount = 0
    tx_window = 0.005  # In seconds
    # bts_list = mcl_get_app_burst_time_size_list(slist, tlist)
    for p in bts_list:
        if pcount > 4000:
            break
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if ct == rt:
            continue
        tdiff = ct - rt
        tdiff = tdiff.total_seconds()
        pd = pd + int(p.dlen) * 8
        th = pd / tdiff
        pcount += 1
        pt = ct
        pth.append(th)
        pindex.append(tdiff)
        # pindex.append(pcount)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_app_inst_bthroughput(fp, bts_list):
    import sys
    from datetime import timedelta
    from datetime import datetime
    pt = 0
    pt_calc = 0
    pd = 0
    ct = 0
    lt = 0
    tdiff = 0
    tdiff_off = 0
    pcount = 0
    pth = []
    pindex = []
    th = 0
    rcount = 0
    tx_window = 0.005250  # In seconds
    # bts_list = mcl_get_app_burst_time_size_list(slist, tlist)
    for p in bts_list:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        if 5000 == int(p.dlen):
            # print("IGNORED PD = " + str(p.dlen))
            continue
        # print("PD = " + str(p.dlen))
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        if 0 == pt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            pt = ct
            print("Reference time =" + str(pt))
            pt_calc = ct
            pt_calc = pt_calc - timedelta(milliseconds=125)
            # print(ct)
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if ct == pt:
            rcount += 1
            pcount += 1
            pd = int(p.dlen) * 8
            if tdiff is not 0:
                th = pd / tdiff
                output_data = "Using previous tdiff = " + str(tdiff) + " " + str(rcount) + '\n'
                mcl_fwrite(DEBUG, fp, output_data)
            else:
                th = 0
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        rcount = 0
        tdiff = (ct - pt)
        tdiff = tdiff.total_seconds()
        pd = int(p.dlen) * 8
        th = pd / tdiff
        '''
        if th > 2000000:
            th = 1000000
        '''
        pcount += 1
        pth.append(th)
        pindex.append(pcount)
        if pd != 40000:
            tdelta = (tdiff - tx_window) * 1000
            pt = pt + timedelta(milliseconds=tdelta)  # ct
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        pt_calc += timedelta(milliseconds=5.250)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(pt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_app_bdelay_diff(fp, bts_list):
    import sys
    from datetime import timedelta
    from datetime import datetime
    pt = 0
    pt_calc = 0
    pd = 0
    ct = 0
    lt = 0
    tdiff = 0
    tdiff_off = 0
    pcount = 0
    pth = []
    pindex = []
    rcount = 0
    rt = 0
    tx_window = 0.005  # In seconds
    for p in bts_list:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        if 0 == pt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            pt = ct
            rt = ct
            pcount += 1
            pth.append(tdiff)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(tdiff) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        tdiff = ct - pt
        tdiff = tdiff.total_seconds()
        tdiff = tdiff * 1000  # Converting to milliseconds
        # pth.append(tdiff)
        if tdiff == 0:
            th = 0
        else:
            th = float(p.dlen) / tdiff
        pth.append(th)
        pcount += 1
        # pindex.append(pcount)
        tdiff = ct - rt
        tdiff = tdiff.total_seconds()
        pindex.append(tdiff)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(tdiff) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        if ct != pt:
            pt = ct
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(pt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + '\n'
    print(output_data)
    output_data = str(tdiff)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_app_bth_diff(fp, ref_bth_list, bth_list):
    pcount = 0
    pth = []
    pindex = []
    for ref_th in ref_bth_list:
        c_th = bth_list.pop(0)
        output_data = str(pcount) + " data " + str(ref_th) + ' ' + str(c_th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        thdiff = abs(ref_th - c_th)
        minth = min(ref_th, c_th)
        if minth == 0:
            thdiff = 0
        else:
            thdiff = thdiff / min(ref_th, c_th)
        output_data = str(pcount) + " res " + str(thdiff) + ' ' + str(minth) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        pcount += 1
        pth.append(thdiff)
        pindex.append(pcount)
        if 0 == len(bth_list):
            break
    return pindex, pth


def mcl_calc_app_inst_athroughput(fp, plist):
    from datetime import datetime
    lplist = len(plist)
    # print("In app throughput " + str(lplist))
    pt = 0
    rt = 0
    pd = 0
    ct = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    for p in plist:
        output_data = str(p.dtime) + ' ' + str(p.dlen) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        ct = p.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = ct
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + \
                          str(tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        if pt == ct:
            pd = pd + p.dlen
            continue
        tdiff = ct - rt
        tdiff = tdiff.total_seconds()
        if tdiff < 0.01:
            continue
        pd = pd + p.dlen
        th = (pd * 1000 * 8) / (tdiff * 1000)
        pcount += 1
        pt = ct
        pth.append(th)
        pindex.append(pcount)
        output_data = str(pcount) + ' ' + str(p.dtime) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ct) + ' ' + str(
            tdiff) + ' ' + str(th) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    output_data = "Data = " + str(pd) + " NumPkt = " + str(pcount) + " OrgT = " + str(rt) + " LastT = " + str(
        ct) + " TDiff = " + str(tdiff) + " AvgpktS = " + str(pd / pcount) + " AvgTh = " + str(pd / tdiff) + '\n'
    print(output_data)
    output_data = str(pth)
    mcl_fwrite(DEBUG, fp, output_data)
    output_data = str(pindex)
    mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_get_app_athroughput_list(atype, app_data_info):
    plist = []
    fname = "input_data/pcap/" + str(atype) + "/" + str(atype) + "_data.txt"
    print(fname)
    if not os.path.exists(fname):
        return app_data_info
    fp = open(fname, "r")
    line = fp.readline()
    line = line.rstrip('\n')
    while line != "":
        line = line.split('#')
        pdata = dinfo_struct(str(line[0]), int(line[1]))
        plist.append(pdata)
        line = fp.readline()
        line = line.rstrip('\n')
    print("Filling "+str(atype))
    app_data_info[atype] = plist
    fp.close()
    return app_data_info


def mcl_calc_per_app_data_cdf(fp, plist):
    import numpy as np
    pthcdf = []
    # plist = mcl_get_app_athroughput_list()
    # print(plist)
    pindex, pd = mcl_calc_per_app_data(fp, plist)
    # print(pth)
    pd_len = len(pd)
    # print("PTH_LEN = "+str(pth_len))
    pd_max = 15000000
    max_pd = max(pd)
    # print("PD_MAX = " + str(max_pd))
    pth_index = np.arange(0, pd_max, 1000000)
    # print(pth_index)
    # i = 0
    # for dlen in pd:
    #    print(str(i) + ":" + str(dlen) + "\n")
    #    i += 1
    # print("pdlen = "+str(pd_len))
    for i in pth_index:
        pcdfc = 0;
        for dlen in pd:
            # print(str(i)+":"+str(dlen) + "\n")
            if dlen*1000 < i:
                pcdfc += 1
        # print("PCDFC = "+str(pcdfc))
        pdcdf = pcdfc / pd_len
        pthcdf.append(pdcdf)
        # if 1 == pdcdf:
        #    print("PDCDF  =1 for "+str(i))
    return pth_index, pthcdf


def mcl_calc_per_app_data_tdiff_cdf(fp, plist):
    import numpy as np
    ptdiffcdf = []
    # plist = mcl_get_app_athroughput_list()
    # print(plist)
    pindex, ptdiff = mcl_calc_per_app_data_tdiff(fp, plist)
    i = 0
    for tdiff in ptdiff:
        print(str(i) + ":" + str(tdiff) + "\n")
        i += 1
    # print(pth)
    ptdiff_len = len(ptdiff)
    # print("PTH_LEN = "+str(pth_len))
    ptdiff_max = 100
    max_pd = max(ptdiff)
    print("TDIFF_MAX = " + str(max_pd))
    ptdiff_index = np.arange(0, ptdiff_max, 10)
    # print(pth_index)
    print("pdlen = "+str(ptdiff_len))
    for i in ptdiff_index:
        pcdfc = 0
        for tdiff in ptdiff:
            # print(str(i)+":"+str(dlen) + "\n")
            if tdiff < i:
                pcdfc += 1
        # print("PCDFC = "+str(pcdfc))
        pdcdf = pcdfc / ptdiff_len
        ptdiffcdf.append(pdcdf)
        # if 1 == pdcdf:
        #    print("PDCDF  =1 for "+str(i))
    return ptdiff_index, ptdiffcdf


def mcl_calc_app_athroughput_cdf(fp, plist):
    import numpy as np
    pthcdf = []
    # plist = mcl_get_app_athroughput_list()
    # print(plist)
    pindex, pth = mcl_calc_app_athroughput(fp, plist)
    # print(pth)
    pth_len = len(pth)
    # print("PTH_LEN = "+str(pth_len))
    pth_max = 15000
    max_th = max(pth)
    print("PTH_MAX = " + str(max_th))
    pth_index = np.arange(0, pth_max, 1000)
    # print(pth_index)
    for i in pth_index:
        pcdfc = 0;
        for th in pth:
            # print(str(th)+":"+str(i))
            if th / 1000 < i:
                pcdfc += 1
        # print("PCDFC = "+str(pcdfc))
        pthcdf.append(pcdfc / pth_len)
        pcdfc = 0
    return pth_index, pthcdf, max_th


def mcl_calc_app_bthroughput_cdf(fp, plist):
    import numpy as np
    pthcdf = []
    # plist = mcl_get_app_athroughput_list()
    # print(plist)
    pindex, pth = mcl_calc_app_runavg_bthroughput(fp, plist)
    # print(pth)
    pth_len = len(pth)
    # print("PTH_LEN = "+str(pth_len))
    pth_max = 15000
    max_th = max(pth)
    print("PTH_MAX = " + str(max_th))
    pth_index = np.arange(0, pth_max, 1000)
    # print(pth_index)
    for i in pth_index:
        pcdfc = 0;
        for th in pth:
            # print(str(th)+":"+str(i))
            if th / 1000 < i:
                pcdfc += 1
        # print("PCDFC = "+str(pcdfc))
        pthcdf.append(pcdfc / pth_len)
        pcdfc = 0
    return pth_index, pthcdf, max_th


def mcl_get_app_bthroughput_list(atype, app_bdata_info):
    plist = []
    fname = "input_data/pcap/" + str(atype) + "/" + str(atype) + "_bdata.txt"
    print(fname)
    if not os.path.exists(fname):
        return app_bdata_info
    fp = open(fname, "r")
    line = fp.readline()
    line = line.rstrip('\n')
    while line != "":
        line = line.split("#")
        pa = dinfo_struct(line[0], line[1])
        plist.append(pa)
        line = fp.readline()
        line = line.rstrip('\n')
    app_bdata_info[atype] = plist
    fp.close()
    return app_bdata_info


def mcl_get_app_burst_size_info_list(atype, app_bsize_info):
    import re
    fname = "input_data/pcap/" + str(atype) + "/" + str(atype)
    print(fname)
    if not os.path.exists(fname):
        print("Input file does not exists........................")
        return app_bsize_info
    fp = open(fname, "rb")
    data = str(fp.readline())
    rtext = 'BURST-END:([0-9][0-9][0-9][0-9])'
    plist = re.findall(rtext, data, re.IGNORECASE)
    app_bsize_info[atype] = plist
    fp.close()
    return app_bsize_info


def mcl_calc_app_throughput_cdf(fp, plist):
    import numpy as np
    pthcdf = []
    pindex, pth = mcl_calc_app_runavg_throughput(fp, plist)
    pth_len = len(pth)
    print("PTH_LEN = " + str(pth_len))
    pth_max = 3
    print("PTH_MAX = " + str(pth_max))
    pth_index = np.arange(0, pth_max, 0.1)
    print(pth_index)
    for i in pth_index:
        pcdfc = 0;
        for th in pth:
            # print(str(th)+":"+str(i))
            if th / 1000 < i:
                pcdfc += 1
        # print("PCDFC = "+str(pcdfc))
        pthcdf.append(pcdfc / pth_len)
        pcdfc = 0
    return pth_index, pthcdf


def mcl_get_app_test_label(app, typeid):
    app = app.split("_")[0]
    if typeid == 1:
        # return str(app) + "_STORED"
        return str(app)
        # return str(app) + "_625000"
    elif typeid == 2:
        # return str(app)+"_500KB_BURST"
        # return str(app) + "_ORG_WP"
        return str(app) + "_NoSNI"
        # return str(app) + "_1250000"
    elif typeid == 0:
        # return str(app)+"_50KB_BURST"
        # return str(app) + "_ORG_NP"
        # return str(app) + "_2Mbps"
        # return str(app) + "_312500"
        return str(app)
    elif typeid == 3:
        # return str(app)+"_1MB_BURST"
        # return str(app) + "_ORG_WVPN"
        return str(app) + "_CorrectSNI"
        # return str(app) + "_2500000"
    elif typeid == 4:
        # return str(app) + "_ORG"
        return str(app) + "_10Mbps"
    elif typeid == 5:
        return str(app) + "_STORED"
    elif typeid == 6:
        return str(app) + "_STORED"
    elif typeid == 7:
        return str(app) + "_STORED"
    elif typeid == 8:
        return str(app) + "_STORED"
    elif typeid == 9:
        return str(app) + "_STORED"
    else:
        print(str(typeid) + " : Wrong test typeid ")
        sys.exit()


def mcl_perform_area_test(app1, app2):
    import numpy as np
    from numpy import trapz
    mth = th_max[app1]
    if mth < th_max[app2]:
        mth = th_max[app2]
    area = trapz(app_th[app1], app_th[app2])
    norm_area = area / mth
    print("Norm area =", norm_area)
    tr = False
    return tr


def mcl_calc_app_data_cdf(fp, app_data_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            app_data = app_data_info[apptype].copy()
            pindex, pth = mcl_calc_per_app_data_cdf(afp, app_data)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Server transmission speed (bps)', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/raathcdf.png')
    plt.show()
    return adata_cdf


def mcl_calc_app_data_tdiff_cdf(fp, app_data_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            app_data = app_data_info[apptype].copy()
            pindex, pth = mcl_calc_per_app_data_tdiff_cdf(afp, app_data)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Inter-burst arrival time (ms)', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/raathcdf.png')
    plt.show()


def mcl_calc_athroughput_cdf(fp, app_data_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            app_data = app_data_info[apptype].copy()
            pindex, pth, max_th = mcl_calc_app_athroughput_cdf(afp, app_data)
            th_max[apptype] = max_th
            app_th[apptype] = pth
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Cumulative Throughput (kbps)', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/raathcdf.png')
    plt.show()


def mcl_calc_bthroughput_cdf(fp, bts_info_list):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            bts_list = bts_info_list[apptype].copy()
            pindex, pth, max_th = mcl_calc_app_bthroughput_cdf(afp, bts_list)
            th_max[apptype] = max_th
            app_th[apptype] = pth
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Cumulative Burst Throughput (kbps)', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/rabthcdf.png')
    plt.show()


def mcl_calc_throughput_cdf(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype].copy()
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_throughput_cdf(afp, pkts)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Throughput (kbps)', fontsize=12)
    plt.ylabel('CDF', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/rathcdf.png')
    plt.show()


def mcl_calc_runavg_throughput(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_runavg_throughput(afp, pkts)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Time (in Seconds)', fontsize=12)
    plt.ylabel('Cumulative Throughput(bps)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/rath.png')
    plt.show()


def mcl_calc_inst_throughput(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype]
            fname = "output_data/pth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_inst_throughput(afp, pkts)
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel)
            mcl_fclose(afp)
    plt.xlabel('Packet index')
    plt.ylabel('Instantaneous Throughput(kbps)')
    ax = plt.subplot(111)
    ax.legend()
    plt.savefig('output_data/instth.png')
    # plt.show()


def mcl_calc_time_window_avg_throughput(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype]
            fname = "output_data/pth_tw_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            tw = (tout / (3000))
            pindex, pth = mcl_calc_app_time_window_avg_throughput(tw, afp, pkts)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Time Window' + "(Window size=" + str(tw * 1000) + "ms)")
    plt.ylabel('Throughput(kbps)')
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=5, length=5, labelsize=13)
    fname = "output_data/twth_" + str(round(tw * 1000)) + "ms.png"
    plt.savefig(fname)
    plt.show()


def mcl_calc_sliding_time_window_avg_throughput(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype]
            fname = "output_data/pth_stw_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            tw = (tout / 1500) * 10
            pindex, pth = mcl_calc_app_sliding_time_window_avg_throughput(tw, afp, pkts)
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel)
            mcl_fclose(afp)
    plt.xlabel('Sliding Time Window' + "(Window size=" + str(tw * 1000) + "ms)")
    plt.ylabel('Throughput(kbps)')
    ax = plt.subplot(111)
    ax.legend()
    fname = "output_data/stwth_" + str(round(tw * 1000)) + "ms.png"
    plt.savefig(fname)
    plt.show()


def mcl_calc_speed(app_data_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_data_info[apptype].copy()
            fname = "output_data/path_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_speed_list(afp, pkts)
            mcl_calc_app_speed(pth)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Segment number', fontsize=12)
    plt.ylabel('Per segment Application Speed(bps)', fontsize=15)
    plt.grid(linestyle='-.', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/speed.png')
    plt.show()


# +Debug
def mcl_print_app_info(app_info):
    for info in app_info:
        print("App : " + str(info[0]))
        x = input()
        print("Index : " + str(info[1]))
        x = input()
        print("Param : " + str(info[2]))


# -Debug


def mcl_plot_app_res(stime, etime, res, applabel, pcolor):
    idx = 0
    sidx = None
    eidx = None
    rtime = stime
    pindex = None
    pth = None
    print(res[0])
    # print(res[1])
    print("Start time = " + str(stime))
    print("End time = " + str(etime))
    for ctime in res[1]:
        if ctime >= stime and sidx is None:
            sidx = idx
            pindex = []
            pth = []
        if ctime >= etime and eidx is None:
            eidx = idx
            break
        if pindex is not None and pth is not None:
            deltime = ctime - rtime
            pindex.append(deltime / 10)
            pth.append(res[2][idx])
        idx += 1
    print(str(sidx) + ":" + str(eidx))
    # print(pth)
    plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)


def mcl_get_measured_th_time_range(app_res):
    stime = None
    etime = None
    # Get the overlapping measurement duration
    for res in app_res:
        # print(res[0])
        # print(res[1])
        tlist = res[1]
        rlen = len(tlist)
        cstime = tlist[0]
        cetime = tlist[rlen - 1]
        if stime is None:
            stime = cstime
        if etime is None:
            etime = cetime
        if cstime > stime:
            stime = cstime
        if cetime < etime:
            etime = cetime
    print("in mcl_get_measured_th_time_range : " + str(stime) + ":" + str(etime))
    return stime, etime


def mcl_plot_perf_param(app_res, alignt):
    start_time = None
    end_time = None
    if alignt:
        start_time, end_time = mcl_get_measured_th_time_range(app_res)
    for res in app_res:
        apptype = res[0]
        app = apptype.split("_")
        # print("App : " + str(app[0]) + "  " + str(app[1]))
        idx = app.pop()
        pcolor = app_to_color_map[apptype]
        applabel = mcl_get_app_test_label(app[0], int(idx))
        mcl_plot_app_res(start_time, end_time, res, applabel, pcolor)


def mcl_get_measured_time_range(app_res):
    # print("mcl_get_measured_time_range")
    stime = None
    etime = None
    # Get the overlapping measurement duration
    found = False
    for res in app_res:
        # print(res[0])
        # print(res[1])
        tlist = res[1]
        rlen = len(tlist)
        # print("rlen of "+ str(res[0]) + " is " + str(rlen))
        ct = tlist[0].dtime
        # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cstime = ct #.timestamp()
        # print(str(res[0]) + " cstime : " + str(cstime))
        ct = tlist[rlen - 1].dtime
        # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        cetime = ct #.timestamp()
        # print(str(res[0]) + " cetime : " + str(cetime))
        if stime is None:
            stime = cstime
            # print(str(res[0])+" stime : "+str(stime))
        else:
            for i in range(0, rlen - 1):
                ct = tlist[i].dtime
                # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
                cstime = ct #.timestamp()
                # print("cstime = " + str(cstime) + ":" + str(stime))
                found = False
                if cstime <= stime:
                    stime = cstime
                    # print(str(res[0]) + " stime : " + str(stime))
                    found = True
                    break
                # print(str(res[0])+" stime : "+str(stime))
            # print("Found = "+str(found))
            if not found:
               ct = tlist[0].dtime
               # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
               stime = ct#.timestamp()
        if etime is None:
            etime = cetime
            # print("Initial :" + str(res[0]) + " etime : " + str(etime))
        else:
            for j in range(rlen - 1, 0, -1):
                # print("index = "+str(j))
                ct = tlist[j].dtime
                # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
                cetime = ct#.timestamp()
                # print("cetime = " + str(cetime) + ":" + str(etime))
                found = False
                if cetime >= etime:
                    etime = cetime
                    # print("Updated :" + str(res[0]) + " etime : " + str(etime))
                    found = True
                    break
            if not found:
                ct = tlist[rlen-1].dtime
                # ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
                etime = ct#.timestamp()
                # print("(False)Updated :" + str(res[0]) + " etime : " + str(etime))
                # print(str(res[0])+" etime : "+str(etime))
        # x = input()
    # print("in mcl_get_measured_time_range : " + str(stime) + ":" + str(etime))
    return stime, etime


# TODO
def mcl_get_slot_stats_dy(tapp, alist, ththr):
    global th_diff_h2l
    global th_per_app
    global min_num_ts
    c_th_diff_h2l = []
    n_l = 0
    n_h = 0
    sn = 0
    n_lc = 0
    n_lc_h = 0
    dc = 0
    pdc = 0
    cth = 0
    #fname = "output_data/" + str(tapp) + "_nldata.txt"
    #fp = open(fname, "w")
    #output_data = str(tapp) + "\n"
    #fp.write(output_data)
    for data in alist:
        hth = 0
        tth = 0
        output_data = str(data[1].param2) + "\n"
        for ainfo in data:
            cth = ainfo.param2
            #output_data += str(cth) + "   :   "
            if ainfo.param2 > hth:
                hth = ainfo.param2
            if ainfo.app == tapp:
                tth = ainfo.param2
            if ainfo.app not in th_per_app:
                th_per_app[ainfo.app] = []
            th_per_app[ainfo.app].append(ainfo.param2/1000000)
        th_diff = hth - tth
        #output_data += str(hth) + "   :    " + str(tth) + "   :   " + str(hth - tth) + "   :   " + str(ththr)
        if hth - tth >= ththr:   #1000000:
            #output_data += "   :   " + "Y" + "\n"
            n_l += 1
            if sn in nl_ps:
                nl_ps[sn] += 1
            else:
                nl_ps[sn] = 1
            pdc += 1
            if pdc == dc + 1:
                n_lc += 1
            else:
                pdc = dc + 1
                if n_lc > n_lc_h:
                    n_lc_h = n_lc
                n_lc = 0
        else:
            #output_data = str(data) + "\n"
            #output_data += str(cth) + "   :   "
            #output_data += str(hth) + "   :    " + str(tth) + "   :   " + str(hth - tth) + "   :   " + str(ththr)
            #output_data += "   :   " + "N" + "\n"
            n_h += 1
        #fp.write(output_data)
        if th_diff > 0:
            th_diff_h2l.append(th_diff/ththr)
        sn += 1
        dc += 1
    if sn < min_num_ts:
        min_num_ts = sn
    #fp.close()
    # print("SN : " + str(sn) + " Min num TS : " + str(min_num_ts))
    return n_l, n_h, c_th_diff_h2l, n_lc



def mcl_get_slot_stats(tapp, alist):
    global th_diff_h2l
    global th_per_app
    global min_num_ts
    c_th_diff_h2l = []
    n_l = 0
    n_h = 0
    sn = 0
    for data in alist:
        hth = 0
        tth = 0
        for ainfo in data:
            if ainfo.param2 > hth:
                hth = ainfo.param2
            if ainfo.app == tapp:
                tth = ainfo.param2
            if ainfo.app not in th_per_app:
                th_per_app[ainfo.app] = []
            th_per_app[ainfo.app].append(ainfo.param2/1000000)
        th_diff = hth - tth
        if hth - tth >= MAX_TD_THDIFF:   #1000000:
            # print(str(hth) + ":" + str(tth) + ":" + str(hth - tth))
            n_l += 1
            if sn in nl_ps:
                nl_ps[sn] += 1
            else:
                nl_ps[sn] = 1
        else:
            n_h += 1
        if th_diff > 0:
            th_diff_h2l.append(th_diff/MAX_TD_THDIFF)
        sn += 1
    if sn < min_num_ts:
        min_num_ts = sn
    # print("SN : " + str(sn) + " Min num TS : " + str(min_num_ts))
    return n_l, n_h, c_th_diff_h2l


def mcl_get_apps_list(alist):
    apps = []
    for astat in alist:
        for app in astat:
            if app.app not in apps:
                apps.append(app.app)
    return apps


def mcl_get_slot_astats(alist):
    # global th_diff_h2l
    n_l = 0
    n_h = 0
    astat_list = []
    apps = mcl_get_apps_list(alist)
    # print(apps)
    for app in apps:
        n_l, n_h, c_th_diff_h2l = mcl_get_slot_stats(app, alist)
        astat = app_info(app, n_l, n_h)
        astat_list.append(astat)
        # th_diff_h2l.append(c_th_diff_h2l)
    return astat_list


def mcl_get_slot_astats_dy(alist, ththr, slthr):
    # global th_diff_h2l
    n_l = 0
    n_h = 0
    astat_list = []
    apps = mcl_get_apps_list(alist)
    # print(apps)
    for app in apps:
        n_l, n_h, c_th_diff_h2l, n_lc = mcl_get_slot_stats_dy(app, alist, ththr)
        astat = app_info(app, n_l, n_h)
        astat_list.append(astat)
        # th_diff_h2l.append(c_th_diff_h2l)
    return astat_list, n_lc


def mcl_get_indexed_app_param_list(app_res, n_t):
    # import collections
    # app_info = collections.namedtuple("app_info", ["app", "param"])
    app_info_list = []
    count = 0
    while count < n_t:
        th_list = []
        # print("Count = "+str(count))
        for app in app_res:
            capp_name = app.app
            capp_ct = app.param1[count]
            capp_th = app.param2[count]
            capp_info = app_info(capp_name, capp_ct, capp_th)
            th_list.append(capp_info)
        app_info_list.append(th_list)
        count += 1
    return app_info_list


def mcl_get_th_list_size(app_res):
    n_t = None
    for app in app_res:
        l = len(app.param2)
        # print("Length = "+str(l))
        if None is n_t or l < n_t:
            n_t = l
            # print("n_t = " + str(n_t))
    return n_t


def mcl_get_lhs(tapp, alist):
    n_l = 0
    n_h = 0
    n_s = 0
    for app in alist:
        # print(str(tapp) + ":" + str(app.app))
        if str(app.app) == str(tapp):
            # print("Test app : " + str(app))
            n_l = app.param1
            n_h = app.param2
    for app in alist:
        if str(app.app) != str(tapp):
            # print("Other app : " + str(app.app))
            if n_l - 2 < app.param1 < n_l + 2:
                n_s += 1
    return n_l, n_h, n_s


def mcl_detect_td_thr(n_t, n_l, n_h, n_s):
    td = "not detected"
    if n_l >= 0.8 * n_t:
        td = "detected"
    elif 0.6 * n_l <= n_l < 0.8 * n_l:
        if n_s >= 1:
            td = "not detected"
        else:
            td = "detected"
    else:
        td = "not detected"
    return td


def mcl_detect_td_thr_dy(n_t, n_l, n_h, n_s, slthr):
    td = "not detected"
    soff1 = 1 - slthr
    soff2 = 1 - 2*slthr
    if n_l >= soff1 * n_t:
        td = "detected"
    elif soff2 * n_l <= n_l < soff1 * n_l:
        if n_s >= 1:
            td = "not detected"
        else:
            td = "detected"
    else:
        td = "not detected"
    return td


def mcl_td_detect_thr_params_dy(tapp, app_res, ththr, slthr):
    # print("Detecting thr params")
    n_s = 0
    n_t = mcl_get_th_list_size(app_res)
    app_info_list = mcl_get_indexed_app_param_list(app_res, n_t)
    # print("app_th = " +str(app_info_list[15]))
    # n_l, n_h = mcl_get_slot_stats(test_app, app_infApp TD statuso_list)
    astat_list, n_lc = mcl_get_slot_astats_dy(app_info_list, ththr, slthr)
    n_l, n_h, n_s = mcl_get_lhs(tapp, astat_list)
    # nl_nt = int((n_l/n_t)*100)
    nl_nt = int((n_lc/n_t)*100)
    nl_count.append(nl_nt)
    # x = input()
    # print(str(n_t) + ":" + str(n_l) + ":" + str(n_h) + ":" + str(n_s))
    td = mcl_detect_td_thr_dy(n_t, n_l, n_h, n_s, slthr)
    # print("Threshold Detect : " + str(td))
    if "detected" == td:
        return True
    else:
        return False

def mcl_td_detect_thr_params(tapp, app_res):
    # print("Detecting thr params")
    ththr = 1*1000000
    slthr = 0.2
    n_s = 0
    n_t = mcl_get_th_list_size(app_res)
    app_info_list = mcl_get_indexed_app_param_list(app_res, n_t)
    # print("app_th = " +str(app_info_list[15]))
    # n_l, n_h = mcl_get_slot_stats(test_app, app_info_list)
    astat_list = mcl_get_slot_astats_dy(app_info_list, ththr, slthr)
    n_l, n_h, n_s = mcl_get_lhs(tapp, astat_list)
    nl_nt = int((n_l/n_t)*100)
    nl_count.append(nl_nt)
    # x = input()
    # print(str(n_t) + ":" + str(n_l) + ":" + str(n_h) + ":" + str(n_s))
    td = mcl_detect_td_thr_dy(n_t, n_l, n_h, n_s, slthr)
    # print("Threshold Detect : Traffic differentiation " + str(td))
    if "detected" == td:
        return True, nl_nt
    else:
        return False, nl_nt



def mcl_get_th_high_time(ltime, alist, tapp, count):
    htime = 0
    fth = 0
    hth = 0
    ilist = alist[count]
    for item in ilist:
        if item.app == tapp:
            ftime = item.param1
            fth = item.param2
    print("  Count =" + str(count))
    print("  Low Th = " + str(fth) + "Low Time = " + str(ltime))
    # print("Input time = "+str(ltime))
    # print("Found time ="+str(ftime))
    while count != 0:
        ilist = alist[count]
        for item in ilist:
            if item.app == tapp:
                thdiff = item.param2 - fth
                print("  Count = "+str(count) + " ThDiff = "+str(thdiff))
                if thdiff >= 1000000:
                    htime = item.param1
                    hth = item.param2
                    break
        if htime != 0:
            break
        count -= 1
    print("  High Th = "+ str(hth) + "High Time = " + str(htime) )
    print("  Count =" + str(count))
    return htime


def mcl_get_app_freq_n_avg(tapp, app_info_list):
    pavg = 0
    freq = 0
    chigh = 0
    clow = 0
    cdur = 0
    ldetect = False
    ncycle = 0
    tstart = 0
    tend = 0
    count = 0
    pthigh = 0
    for ainfo in app_info_list:
        for info in ainfo:
            if info.app == tapp:
                if chigh <= info.param2:
                    # print("High detected : " + str(info.param2) + " : " + str(info.param1))
                    if True is ldetect:
                        ncycle += 1
                        ctime = pthigh - info.param1
                        # print("cycle detected : " + str(ncycle) + " : " + str(ctime))
                        ldetect = False
                    clow = 0
                    chigh = info.param2
                    tstart = info.param1
                else:
                    clow = info.param2
                    cdiff = chigh - clow
                    # print("Diff : " + str(cdiff))
                    if chigh - clow >= 1000000:
                        # print("Low detected : " + str(info.param2) + " : " + str(info.param1))
                        ldetect = True
                        chigh = clow + 1000000
                        pthigh = mcl_get_th_high_time(info.param1, app_info_list, tapp, count)
        count += 1
    # print("Number of cycles = " + str(ncycle))
    return pavg, freq


def mcl_get_td_ranges(tapp, app_info_list):
    cth = 0
    ctime = 0
    chigh = 0
    clow = 0
    htstart = 0
    ltstart = 0
    hdetect = False
    ldetect = False
    tranges = []
    for ainfo in app_info_list:
        for info in ainfo:
            if info.app == tapp:
                cth = info.param2
                ctime = info.param1
                if chigh <= cth:
                    chigh = cth
                    hdetect = True
                    htstart = ctime
                    if ldetect is True and chigh - clow >= 1000000:
                        trange = ctime - ltstart
                        if trange <= MAX_DIS_TIME:
                            tranges.append(trange)
                        # print("  Time Range : " + str(trange))
                        clow = 0
                        ldetect = False
                        ltstart = 0
                else:
                    clow = cth
                    ldetect = True
                    ltstart = ctime
                    if hdetect is True and chigh - clow >= 1000000:
                        trange = ctime - htstart
                        if trange <= MAX_DIS_TIME:
                            tranges.append(trange)
                        # print("  Time Range : " + str(trange))
                        chigh = 0
                        hdetect = False
                        htstart = 0
    return tranges


def mcl_detect_td_ranges(t_total, dranges):
    tdrange = 0
    for drange in dranges:
        tdrange += drange
    frac = tdrange/t_total
    # print("Total time = "+str(t_total))
    # print("High th variations time ="+str(tdrange))
    # print("Fraction = "+str(frac))
    if frac >= 0.3:
        td = "detected"
    else:
        td = "not detected"
    return td


def mcl_get_td_detect_range_params(tapp, app_res, t_total):
    n_t = mcl_get_th_list_size(app_res)
    app_info_list = mcl_get_indexed_app_param_list(app_res, n_t)
    dranges = mcl_get_td_ranges(tapp, app_info_list)
    td = mcl_detect_td_ranges(t_total, dranges)
    print("Range : Traffic differentiation " + str(td))
    if "detected" == td:
        return True
    else:
        return False


def mcl_align_stat_end_time(alist, app_data_info):
    app_res = []
    # print("Applist = "+str(alist))
    for app in alist:
        app_opt = alist[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_data_info[apptype].copy()
            capp_info = app_info(apptype, pkts, [])
            app_res.append(capp_info)
    start_time, end_time = mcl_get_measured_time_range(app_res)
    return start_time, end_time


def mcl_calc_time_windowed_athroughput_dy(tapp, alist, app_data_info, max_slot_time, ththr, slthr, st):
    app_res = []
    # print("Calculating time windowed throughput")
    # TODO - Align start and end of time frame for all Apps
    start_time, end_time = mcl_align_stat_end_time(alist, app_data_info)
    # print("Calculated range = "+str(start_time) + ":" + str(end_time))
    # print("Total time duration = "+str(end_time - start_time))
    t_time = end_time - start_time
    # x = input()
    td_range = False
    td_thr = False
    tpth = tapp
    PLT_ON = 0
    for app in alist:
        app_opt = alist[app]
        aolen = len(app_opt)
        # print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # print("Service : "+str(apptype))
            pkts = app_data_info[apptype].copy()
            #fname = "output_data/path_" + str(apptype) + ".txt"
            #afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            afp = None
            pindex, pth = mcl_calc_app_time_windowed_athroughput(afp, pkts, start_time, end_time, st)
            # pindex, pth = mcl_calc_app_data_windowed_athroughput(afp, pkts, start_time, end_time, max_slot_time)
            # print("APP : " + str(apptype) + " : " + str(pindex))
            # print("path len = " + str(len(pth)))
            capp_info = app_info(apptype, pindex, pth)
            app_res.append(capp_info)
            pcolor = app_to_color_map.get(apptype, "blue")
            # print("Selected color : "+str(pcolor))
            applabel = mcl_get_app_test_label(app, i)
            # print(app)
            # print(pindex)
            if PLT_ON == 1:
                plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
            # print(str(apptype) + ":" + str(tapp))
            # if apptype == tapp:
            tpth = pth
            # print("Copying pth : " + str(tpth))
    if PLT_ON == 1:
        t = time.time()
        plt.xlabel('Seconds', fontsize=12)
        plt.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
        plt.grid(linestyle='--', linewidth=2)
        ax = plt.subplot(111)
        ax.legend()
        ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
        plt.tick_params(width=2, length=5, labelsize=13)
        plt.savefig("output_data/" + str(t) + "_twraath.png")
        # plt.show()
    arlist = app_res.copy()
    td_thr = mcl_td_detect_thr_params_dy(tapp, arlist, ththr, slthr)
    t_total = (end_time - start_time)
    arlist = app_res.copy()
    # td_range = mcl_get_td_detect_range_params(tapp, arlist, t_total)
    # x = input()
    return td_thr, t_time, tpth





def mcl_calc_time_windowed_athroughput(tapp, alist, app_data_info, max_slot_time):
    app_res = []
    # print("Calculating time windowed throughput")
    # TODO - Align start and end of time frame for all Apps
    start_time, end_time = mcl_align_stat_end_time(alist, app_data_info)
    # print("Calculated range = "+str(start_time) + ":" + str(end_time))
    # print("Total time duration = "+str(end_time - start_time))
    t_time = end_time - start_time
    # x = input()
    td_range = False
    td_thr = False
    tpth = tapp
    PLT_ON = 0
    for app in alist:
        app_opt = alist[app]
        aolen = len(app_opt)
        # print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # print("Service : "+str(apptype))
            pkts = app_data_info[apptype].copy()
            fname = "output_data/path_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_time_windowed_athroughput(afp, pkts, start_time, end_time, max_slot_time)
            # pindex, pth = mcl_calc_app_data_windowed_athroughput(afp, pkts, start_time, end_time, max_slot_time)
            # print("APP : " + str(apptype) + " : " + str(pindex))
            # print("path len = " + str(len(pth)))
            capp_info = app_info(apptype, pindex, pth)
            app_res.append(capp_info)
            pcolor = app_to_color_map.get(apptype, "blue")
            # print("Selected color : "+str(pcolor))
            applabel = mcl_get_app_test_label(app, i)
            # print(app)
            # print(pindex)
            if PLT_ON == 1:
                plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
            # print(str(apptype) + ":" + str(tapp))
            # if apptype == tapp:
            tpth = pth
            # print("Copying pth : " + str(tpth))
    if PLT_ON == 1:
        plt.xlabel('Seconds', fontsize=12)
        plt.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
        plt.grid(linestyle='--', linewidth=2)
        ax = plt.subplot(111)
        ax.legend()
        ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
        plt.tick_params(width=2, length=5, labelsize=13)
        plt.savefig('output_data/twraath.png')
        plt.show()
    arlist = app_res.copy()
    td_thr, nl_nt = mcl_td_detect_thr_params(tapp, arlist)
    t_total = (end_time - start_time)
    arlist = app_res.copy()
    # td_range = mcl_get_td_detect_range_params(tapp, arlist, t_total)
    # x = input()
    return td_thr, t_time, tpth, nl_nt


def mcl_calc_runavg_athroughput(alist, app_data_info):
    import matplotlib.pyplot as p
    print("mcl_calc_runavg_athroughput")
    import collections
    p.cla()
    alignt = False
    app_info = collections.namedtuple("app_info", ["app", "idx", "param"])
    app_res = []
    for app in alist:
        app_opt = alist[app]
        aolen = len(app_opt)
        # print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_data_info[apptype].copy()
            fname = "output_data/path_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_athroughput(afp, pkts)
            # print("APP: " + str(app) + " : " + str(pth))
            # x = input()
            capp_info = app_info(apptype, pindex, pth)
            app_res.append(capp_info)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    # mcl_plot_perf_param(app_res, alignt)
    p.xlabel('Packet count', fontsize=12)
    p.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
    p.grid(linestyle='--', linewidth=2)
    ax = p.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    p.tick_params(width=2, length=5, labelsize=13)
    p.savefig('output_data/raath.png')
    p.show()


def mcl_calc_app_data(app_data_info):
    print("mcl_calc_runavg_athroughput")
    import collections
    alignt = True
    app_info = collections.namedtuple("app_info", ["app", "idx", "param"])
    app_res = []
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        # print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_data_info[apptype].copy()
            fname = "output_data/path_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_per_app_data(afp, pkts)
            # print("APP: " + str(app) + " : " + str(pindex)  )
            capp_info = app_info(apptype, pindex, pth)
            app_res.append(capp_info)
            # pcolor = app_to_color_map[apptype]
            # applabel = mcl_get_app_test_label(app, i)
            # plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    mcl_plot_perf_param(app_res, alignt)
    plt.xlabel('Seconds', fontsize=12)
    plt.ylabel('Cumulative Application Throughput(bps)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/raath.png')
    plt.show()



def mcl_calc_inst_athroughput(app_data_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_data_info[apptype]
            fname = "output_data/path_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_inst_athroughput(afp, pkts)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Number of time window', fontsize=12)
    plt.ylabel('Application Throughput(kbps) per tx window', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/iath.png')
    plt.show()


def mcl_calc_runavg_bthroughput(bts_list_info):
    b_th_info = {}
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            # tlist = app_bdata_info[apptype].copy()
            # slist = app_bsize_info[apptype].copy()
            bts_list = bts_list_info[apptype].copy()
            fname = "output_data/pbrath_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_runavg_bthroughput(afp, bts_list)
            b_th_info[apptype] = pth
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Time (in s)', fontsize=12)
    plt.ylabel('Cumulative Burst Throughput(bps)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/rabth.png')
    plt.show()
    return b_th_info


def mcl_calc_inst_bthroughput(bts_list_info):
    b_th_info = {}
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            bts_list = bts_list_info[apptype].copy()
            fname = "output_data/pibth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_inst_bthroughput(afp, bts_list)
            b_th_info[apptype] = pth
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Number of time window', fontsize=12)
    plt.ylabel('Application Throughput(bps) per tx window', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/ibth.png')
    plt.show()
    return b_th_info


def mcl_calc_bdelay_diff(bts_list_info):
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            bts_list = bts_list_info[apptype].copy()
            fname = "output_data/pbth_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_bdelay_diff(afp, bts_list)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            # app = str(app)+"_"+str(app_list[app])
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Number of bursts', fontsize=12)
    plt.ylabel(' Inter burst time (ms)', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/ibddiff.png')
    plt.show()


def mcl_calc_app_iat(fp, plist):
    import decimal as decimal
    l = len(plist)
    pt = 0
    pd = 0
    ct = 0
    pcount = 0
    piat = []
    pindex = []
    seg_size = 625000
    for p in plist:
        ct = p.dtime
        if 0 == pt:
            pt = ct
            continue
        if pt == ct:
            pd = pd + p.dlen
            continue
        if pd < seg_size:
            pd = pd + p.dlen
            continue
        pd = 0
        tdiff = (ct - pt) * 1000
        pcount += 1
        piat.append(tdiff)
        pindex.append(pcount)
        pt = ct
        output_data = str(pcount) + ' ' + str(pd) + ' ' + str(pt) + ' ' + str(ct) + ' ' + str(
            tdiff) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    return pindex, piat


def mcl_plot_data(lid, ld, app):
    f, (ax, ax2) = plt.subplots(2, 1, sharex=True)
    ax.plot(ld)
    ax2.plot(ld)
    ax.set_ylim(2000, 2200)  # outliers only
    ax2.set_ylim(0, 50)  # most of the data
    # hide the spines between ax and ax2
    ax.spines['bottom'].set_visible(False)
    ax2.spines['top'].set_visible(False)
    ax.xaxis.tick_top()
    ax.tick_params(labeltop='off')  # don't put tick labels at the top
    ax2.xaxis.tick_bottom()
    d = .015
    kwargs = dict(transform=ax.transAxes, color='k', clip_on=False)
    ax.plot((-d, +d), (-d, +d), **kwargs)  # top-left diagonal
    ax.plot((1 - d, 1 + d), (-d, +d), **kwargs)  # top-right diagonal

    kwargs.update(transform=ax2.transAxes)  # switch to the bottom axes
    ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)  # bottom-left diagonal
    ax2.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)  # bottom-right diagonal

    # plt.show()


def mcl_calc_iat(fp, alist, app_pkt_info):
    PLT_ON = 0
    for app in alist:
        print(str(app))
        app_opt = alist[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype].copy()
            pcolor = app_to_color_map.get(apptype, "red")
            fname = "output_data/iat_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, piat = mcl_calc_app_iat(afp, pkts)
            # mcl_plot_data(pindex,piat,app)
            applabel = mcl_get_app_test_label(app, i)
            if PLT_ON == 1:
                plt.plot(pindex, piat, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    if PLT_ON == 1:
        plt.xlabel('Burst Number')
        plt.ylabel('Inter-arrival time (ms)')
        plt.grid(linestyle='--', linewidth=2)
        ax = plt.subplot(111)
        ax.legend()
        ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
        plt.tick_params(width=5, length=5, labelsize=13)
        plt.savefig('output_data/iat.png')
        plt.show()


def mcl_calc_app_throughput_var(fp, plist):
    import decimal as decimal
    l = len(plist)
    throughput = 0
    rt = 0
    pd = 0
    ot = 0
    pcount = 0
    pth = []
    pindex = []
    tdiff = 0
    th = 0
    pct = 0
    oth = 0
    pt = 0
    for p in plist:
        output_data = str(p[0]) + ' ' + str(p[1]) + ' ' + str(p[2]) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
        # if pct < 100:
        #    pct += 1
        #    continue
        ot = p[0]
        dt = decimal.Decimal(str(p[0]))
        d = abs(dt.as_tuple().exponent)
        if d < 6:
            ot = ot + 0.000001
        if 0 == rt:
            output_data = "Reference updated \n"
            mcl_fwrite(DEBUG, fp, output_data)
            rt = pt = ot
            # pd = p[2]
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            output_data = str(pcount) + ' ' + str(p[2]) + ' ' + str(pd) + ' ' + str(rt) + ' ' + str(ot) + ' ' + str(
                tdiff) + ' ' + str(th) + '\n'
            mcl_fwrite(DEBUG, fp, output_data)
            continue
        tdiff = ot - rt
        if 1 == pcount:
            #    pd = pd + p[2]
            pcount += 1
            pth.append(th)
            pindex.append(pcount)
            continue
        if tdiff < 0.01:
            #    print(tdiff)
            #    pd = pd + p[2]
            continue
        # if tdiff > 0.1:
        #    tdiff = tdiff - 0.1
        pd = pd + p[2]
        th = pd / (tdiff * 1000)
        th_diff = th - oth
        tdiff = ot - pt
        oth = th
        pt = ot
        if tdiff == 0:
            continue
        dth = th_diff / (tdiff * 1000)
        # print(str(oth) + " " + str(th) + " " + str(th_diff)+ " " + str(tdiff) + "TH="+ str(th) + '\n')
        pcount += 1
        pth.append(dth)
        pindex.append(pcount)
        output_data = str(pcount) + ' ' + str(oth) + ' ' + str(th) + ' ' + str(th_diff) + ' ' + str(rt) + ' ' + str(
            ot) + ' ' + str(tdiff) + ' ' + str(dth) + '\n'
        mcl_fwrite(DEBUG, fp, output_data)
    return pindex, pth


def mcl_calc_throughput_var(app_pkt_info):
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = app_pkt_info[apptype]
            fname = "output_data/pth_var" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_throughput_var(afp, pkts)
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel)
            mcl_fclose(afp)
    plt.xlabel('Number of packets')
    plt.ylabel('Running average Throughput(kbps)')
    ax = plt.subplot(111)
    ax.legend()
    plt.savefig('output_data/th_var.png')
    # plt.show()


def mcl_calc_bth_diff(bth_list_info):
    REF_APP = "NETFLIX_1"
    ref_bth_list = bth_list_info[REF_APP].copy()
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            print(apptype)
            bth_list = bth_list_info[apptype].copy()
            fname = "output_data/bthdiff_" + str(apptype) + ".txt"
            afp = mcl_fopen(DEBUG, fname, "a", "DELETE")
            pindex, pth = mcl_calc_app_bth_diff(afp, ref_bth_list, bth_list)
            pcolor = app_to_color_map[apptype]
            applabel = mcl_get_app_test_label(app, i)
            plt.plot(pindex, pth, label=applabel, markersize=20, linewidth=2, color=pcolor)
            mcl_fclose(afp)
    plt.xlabel('Number of time window', fontsize=12)
    plt.ylabel('Application Throughput(bps) diff per tx window', fontsize=15)
    plt.grid(linestyle='--', linewidth=2)
    ax = plt.subplot(111)
    ax.legend()
    ax.ticklabel_format(style='sci', scilimits=(-2, 3), useLocale=True)
    plt.tick_params(width=2, length=5, labelsize=13)
    plt.savefig('output_data/bthdiff.png')
    plt.show()


def mcl_calc_app_avg_bth(bth_list):
    avg_th = bth_list.pop()
    return avg_th


def mcl_calc_avg_bth(bth_info):
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            atype = str(app) + "_" + str(i)
            bth_list = bth_info[atype]
            th_avg[atype] = mcl_calc_app_avg_bth(bth_list)


def mcl_calc_throughput(fp, app_pkt_info):
    mcl_calc_runavg_throughput(app_pkt_info)
    # mcl_calc_inst_throughput(app_pkt_info)
    # mcl_calc_time_window_avg_throughput(app_pkt_info)
    # mcl_calc_sliding_time_window_avg_throughput(app_pkt_info)
    # mcl_calc_throughput_var(app_pkt_info)


def mcl_get_app_info(adata):
    ainfo = []
    for data in adata:
        ct = data.dtime
        ct = datetime.strptime(ct, '%Y-%m-%d %H:%M:%S.%f')
        ctime = ct.timestamp()
        info = dinfo_struct(ctime, data.dlen)
        ainfo.append(info)
        # print(info)
        # x = input()
    return ainfo


def mcl_generate_app_info_list(app_data_info):
    app_info_list = {}
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            adata = app_data_info[apptype].copy()
            app_info_list[apptype] = mcl_get_app_info(adata)
    return app_info_list


def mcl_calc_athroughput(fp, app_data_info):
    print("mcl_calc_athroughput")
    # if is_speed_test:
    #    mcl_calc_speed(app_data_info)
    # else:
    # mcl_calc_runavg_athroughput(app_list, app_data_info)
    # mcl_calc_app_data(app_data_info)
    # mcl_calc_inst_athroughput(app_data_info)
    app_info_list = mcl_generate_app_info_list(app_data_info)
    # print(app_info_list)
    # x = input()
    mcl_calc_runavg_athroughput(app_list, app_info_list)
    # mcl_calc_time_windowed_athroughput(test_app, app_list, app_info_list, "")
    # mcl_calc_time_windowed_athroughput(app_data_info)
    # mcl_calc_sliding_time_window_avg_throughput(app_pkt_info)
    # mcl_calc_throughput_var(app_pkt_info)


def mcl_calc_bthroughput(fp, bts_list_info):
    bth_info = mcl_calc_runavg_bthroughput(bts_list_info)
    # mcl_calc_bth_diff(bth_info)
    # bth_info = mcl_calc_inst_bthroughput(bts_list_info)
    # mcl_calc_bth_diff(bth_info)
    mcl_calc_avg_bth(bth_info)


def mcl_calc_bdelay(fp, bts_list_info):
    mcl_calc_bdelay_diff(bts_list_info)


def mcl_get_app_data(apptype):
    p_app_data = []
    sfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(apptype) + "\\" + str(apptype) + "_data.txt"
    print("App data file:" + str(sfname))
    fp = open(sfname, "r")
    data = fp.readline()
    for data in fp:
        adata = data.split("#")
        dtime = adata[0]
        dlen = int(adata[1])
        pa = dinfo_struct(dtime, dlen)
        p_app_data.append(pa)
    fp.close()
    dfname = "D:\\Vinod\\Code\\Meas_client\\output_data\\" + str(apptype) + "_data.txt"
    print("Copying " + str(sfname) + " to " + str(dfname))
    os.system("copy {0} {1}".format(sfname, dfname))
    return p_app_data


def mcl_get_app_data_info(debug, map, host):
    app_data_info = {}
    for app in app_list:
        app_opt = app_list[app]
        aolen = len(app_opt)
        #print("AOLEN = " + str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            app_data_info = mcl_get_app_athroughput_list(apptype, app_data_info)
    return app_data_info


def mcl_get_tcp_packet_info(debug: object, map: object, host: object) -> object:
    print("New mcl_get_tcp_packet_info ")
    app_pkt_info = {}
    fp = None
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            pkts = mcl_get_pkt_list(debug, app, i)
            app_pkt_info = mcl_process_sniffed_pkts(fp, pkts, map, host, apptype, app_pkt_info)
    return app_pkt_info


def mcl_get_burst_data_info(debug, map, host):
    app_bdata_info = {}
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            app_bdata_info = mcl_get_app_bthroughput_list(apptype, app_bdata_info)
    return app_bdata_info


def mcl_get_burst_size_info(debug, map, host):
    app_bsize_info = {}
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            app_bsize_info = mcl_get_app_burst_size_info_list(apptype, app_bsize_info)
    return app_bsize_info


def mcl_calc_tcp_performance(debug, map, host):
    app_pkt_info = {}
    fp = None
    app_pkt_info = mcl_get_tcp_packet_info(debug, map, host)
    # mcl_calc_iat(fp,app_pkt_info)
    mcl_calc_throughput(fp, app_pkt_info)


def mcl_calc_app_performance(debug, map, host):
    app_data_info = {}
    fp = None
    app_data_info = mcl_get_app_data_info(debug, map, host)
    mcl_calc_athroughput(fp, app_data_info)
    # mcl_calc_app_data_cdf(fp, app_data_info)
    # mcl_calc_app_data_tdiff_cdf(fp, app_data_info)
    # mcl_calc_athroughput_cdf(fp, app_data_info)
    # tr = mcl_perform_area_test()
    # max_th = mcl_detect_tr_diff()


def mcl_get_burst_time_size_list(app_bsize_info, app_bdata_info):
    bts_list_info = {}
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            atype = str(app) + "_" + str(i)
            fname = "output_data/" + str(atype) + "_bts_list.txt"
            if os.path.exists(fname):
                os.system("del {0}".format(fname))
            fp = open(fname, "a")
            tlist = app_bdata_info[atype].copy()
            slist = app_bsize_info[atype].copy()
            bts_list_info[atype] = mcl_get_app_burst_time_size_list(fp, slist, tlist)
    return bts_list_info


def mcl_get_tr_status(capp):
    th = th_avg[test_app]
    cth = th_avg[capp]
    return tdiff_norm


def mcl_detect_nnvd(tapp):
    tr_status = "Traffic differentiation not detected"
    th = th_avg[tapp]
    max_th = th
    for app in app_list:
        app_opt = app_list[app]
        for i in app_opt:
            atype = str(app) + "_" + str(i)
            cth = th_avg[atype]
            if max_th < cth:
                max_th = cth
    if th > max_th:
        tdiff = 0
    else:
        tdiff = max_th - th
        tdiff_norm = (tdiff / th) * 100
    print("TDiffNorm = " + str(tdiff_norm))
    if tdiff_norm > 1:
        tr_status = "Traffic differentiation detected"
    return tr_status


def mcl_calc_burst_performance(debug, map, host):
    app_data_info = {}
    fp = None
    app_bdata_info = mcl_get_burst_data_info(debug, map, host)
    app_bsize_info = mcl_get_burst_size_info(debug, map, host)
    bts_list_info = mcl_get_burst_time_size_list(app_bsize_info, app_bdata_info)
    mcl_calc_bthroughput(fp, bts_list_info)
    # mcl_calc_bthroughput_cdf(fp, bts_list_info)
    mcl_calc_bdelay(fp, bts_list_info)
    # tr = mcl_perform_area_test("WYNK_1", "GAANA.COM_1")
    # max_th = mcl_detect_tr_diff()
    tr = mcl_detect_nnvd(test_app)
    # print("Result : "+tr)


def mcl_calculate_performance_parameters(debug, map, host):
    # mcl_calc_tcp_performance(debug, map, host)
    mcl_calc_app_performance(debug, map, host)
    # mcl_calc_burst_performance(debug, map, host)


def mcl_analyse_pkts(debug, pkts, map, host):
    app_pkt_info = {}
    fname = "output_data/analyse_pkts.txt"
    fp = mcl_fopen(debug, fname, "a", "DELETE")
    output_data = "Analysing packets" + '\n'
    mcl_fwrite(debug, fp, output_data)
    output_data = str(pkts) + '\n'
    mcl_fwrite(debug, fp, output_data)
    # Get packet list for each app
    app_pkt_info = mcl_process_sniffed_pkts(fp, pkts, map, host, app_pkt_info)
    # Calculate performance for each app
    mcl_calculate_performance_parameters(fp, app_pkt_info)
    fp.close()


def mcl_get_pkt_list(debug, app, typeid):
    plist = []
    # if use_proxy == 1:
    #    fname = "input_data/Pcap/Proxy/"+str(app)+"/pkts_"+str(app)+".pcap"
    # else:
    #    fname = "input_data/Pcap/Noproxy/"+str(app)+"/pkts_"+str(app)+".pcap"
    # fname = "input_data/Pcap/pkts_"+str(app)+".pcap"
    fname = "input_data/Pcap/" + str(app) + "_" + str(typeid) + "/pkts.pcap"
    print(fname)
    plist = rdpcap(fname)
    # print(plist)
    # pcount = mcl_count_num_pkts(plist)
    # print("Num pkts = "+str(pcount))
    apptype = str(app) + "_" + str(typeid)
    sfname = "D:\\Vinod\\Code\\Meas_client\\input_data\\Pcap\\" + str(app) + "_" + str(typeid) + "\\pkts.pcap"
    dfname = "D:\\Vinod\\Code\\Meas_client\\output_data\\" + str(apptype) + ".pcap"
    print("Copying " + str(sfname) + " to " + str(dfname))
    os.system("copy {0} {1}".format(sfname, dfname))
    return plist


def mcl_detect_tr_diff():
    max_th = 0
    avgth = 0
    thcount = 0
    for app in app_list:
        app_opt = app_list[app]
        # aolen = len(app_opt)
        # print("AOLEN = "+str(aolen))
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            th = th_max[apptype]
            avgth += th
            thcount += 1
            if max_th < th:
                max_th = th
    avgth = avgth / thcount
    print("Avg th = " + str(avgth))
    for app in app_list:
        for i in app_opt:
            apptype = str(app) + "_" + str(i)
            thdiff = th_max[apptype] - avgth
            print("Diff from avg th = " + str(thdiff))
    return max_th


def mcl_analyse_pkts_offline(debug, map, host):
    app_pkt_info = {}
    app_data_info = {}
    fname = "output_data/analyse_pkts.txt"
    fp = mcl_fopen(debug, fname, "a", "DELETE")
    output_data = "Analysing packets" + '\n'
    mcl_fwrite(debug, fp, output_data)
    # Get pkts_to_app mapping

    # app_data_info = mcl_get_app_data_info(debug, map, host)
    # app_pkt_info = mcl_get_tcp_packet_info(debug, map, host)
    # Calculate performance for each app
    mcl_calculate_performance_parameters(debug, map, host)
    fp.close()


def mcl_analyse_pkts_main(debug, pkts, map, host):
    if None is pkts:
        mcl_analyse_pkts_offline(debug, map, host)
    else:
        mcl_analyse_pkts(debug, pkts, map, host)


if __name__ == '__main__':
    mcl_analyse_pkts_main(1, None, None, None)
