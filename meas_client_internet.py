# -*- coding: utf-8 -*-

from meas_client_global_const import *
from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite

MAX_BUFF_SIZE = 8192 * 12


def mcl_get_vlen_direct(data, efile):
    import re
    if "Content-Length: " not in str(data):
        efile.write(str(len(data)) + "\n")
        efile.write("Content-Length = 0\n")
        print("Returing vlen=" + str(0))
        return 0
    # fname = "output_data/lpart.txt"
    # fp = mcl_fopen(DEBUG,fname,"a","DELETE")
    # fp = open("output_data/lpart.txt","a")
    # output_data = str(data) + '\n'
    # mcl_fwrite(DEBUG,fp,output_data)
    m = re.search('Content-Length: (\d+)', str(data), re.IGNORECASE)
    vlen = m.group(1)
    output_data = "Returing vlen=" + str(vlen) + '\n'
    # mcl_fwrite(DEBUG,fp,output_data)
    efile.write(output_data)
    print("Returing vlen=" + str(vlen))
    return int(vlen)


def mcl_get_vlen(data, efile):
    if "Content-Length: " not in str(data):
        efile.write("Content-Length = 0\n")
        return 0
    # fname = "output_data/lpart.txt"
    # fp = mcl_fopen(DEBUG,fname,"a","DELETE")
    # fp = open("output_data/lpart.txt","a")
    # output_data = str(data) + '\n'
    # mcl_fwrite(DEBUG,fp,output_data)
    lenpart = str(data).split('Content-Length: ')[1]
    # output_data = "Lenpart="+lenpart+'\n'
    # mcl_fwrite(DEBUG,fp,output_data)
    vlen = (lenpart.split("Date")[0]).strip("\\r\\n")
    # print(vlen)
    output_data = "VLEN = " + str(vlen) + '\n'
    mcl_fwrite(DEBUG, fp, output_data)
    # mcl_fclose(fp)
    return int(vlen)


def mcl_get_all_burst_sizes(data):
    import re
    rtext = 'BURST-END:([0-9][0-9][0-9][0-9])'
    res = re.findall(rtext, data, re.IGNORECASE)
    return res


def mcl_receive_socket(s):
    import select
    import socket
    BURST_SIZE = 65536
    res = None
    while True:
        try:
            # print("Select invoked" + " " + str(s))
            ss = [s]
            r, w, e = select.select(ss, [], ss)
            if e:
                res = "ERROR"
                break
        except socket.timeout as e:
            res = "ERROR"
            break
        except KeyboardInterrupt:
            res = "ERROR"
            break
        try:
            # print("Select done : " + str(res) + " r:" + str(r) + " e:" + str(e) + " w:" + str(w))
            if s in r:
                res = s.recv(BURST_SIZE)
                # print("RES = " + str(res))
                break
        except socket.error as e:
            output_data = "s.recv:" + str(e)
            print(output_data)
            res = "ERROR"
            break
        except socket.timeout as e:
            output_data = "s.recv:" + str(e)
            print(output_data)
            res = "ERROR"
            break
        except KeyboardInterrupt:
            res = "ERROR"
            break
    return res


def mcl_receive_data(s, ofile, efile, app, p_app_data, b_app_data, client_time):
    from datetime import datetime
    import select
    import socket
    from datetime import timedelta
    tlen = 0
    dlen = 0
    vlen = 0
    BURST_SIZE = 65536
    ctime = client_time
    ptime = datetime.now()
    while True:
        try:
            ss = [s]
            # receive data from web server
            # print("Select")
            r, w, e = select.select(ss, [], ss)
            # print("Select Done")
            if e:
                output_data = "Socket in error \n"
                # print(output_data)
                # efile.write(output_data)
                efile.close()
                break
        except socket.timeout as e:
            output_data = "s.recv:" + str(e)
            # print(output_data)
            # efile.write(output_data)
            efile.close()
            break
        except KeyboardInterrupt:
            efile.close()
            break
        try:
            if s in r:
                data = s.recv(BURST_SIZE)
                dtime = datetime.now()
                if ctime is not "INVALID_TIME":
                    if not is_speed_test:
                        print("Client Time = "+str(client_time))
                        tdiff_sec = ((dtime - client_time).total_seconds())/2
                        print("Tdiff sec = "+str(tdiff_sec))
                        ref_time = client_time + timedelta(seconds=tdiff_sec)
                        print("Ref time = " + str(ref_time))
                        output_data = "REF_TIME :" + str(ref_time) + '\n'
                        efile.write(output_data)
                        dtime = ref_time
                        ctime = "INVALID_TIME"
                        dtime = str(dtime)
                    else:
                        ctime = "INVALID_TIME"
                        ptime = dtime
                if vlen == 0:
                    vlen = mcl_get_vlen_direct(data, efile)
                dlen = len(data)
                tlen += dlen
                f = open(ofile, 'ab')
                f.write(data)
                f.close()
                nbursts = str(data).count("BURST-END:")
                pa = dinfo_struct(dtime, nbursts)
                b_app_data.append(pa)
                if not is_speed_test:
                    pa = dinfo_struct(dtime, dlen)
                    p_app_data.append(pa)
                # efile.write("Tlen=" + str(tlen) + " Dlen=" + str(dlen) + '\n')
                if ((vlen < tlen or None is vlen or dlen == 0 or tlen >= MAX_DATA) and b2b_http == 0) or \
                        tlen > MAX_DATA:
                    output_data = str(tlen) + " " + str(vlen) + " " + str(dlen) + " " + str(MAX_DATA) + " " + "Done"
                    efile.write(output_data)
                    efile.close()
                    if is_speed_test:
                        tdiff = (dtime-ptime).total_seconds()
                        # print(str(tdiff) + ":" + str(tlen))
                        pa = dinfo_struct(tdiff, tlen)
                        p_app_data.append(pa)
                    break
        except socket.error as e:
            output_data = "s.recv:" + str(e)
            print(output_data)
            efile.write(output_data)
            efile.close()
            break
        except socket.timeout as e:
            output_data = "s.recv:" + str(e)
            print(output_data)
            efile.write(output_data)
            efile.close()
            break
        except KeyboardInterrupt:
            efile.close()
            break
    return tlen, p_app_data, b_app_data


def mcl_download_file_socket(debug, s, request, fname):
    vlen = 0
    fp = mcl_fopen(debug, "output_data/int_test.txt", "a", "NA")
    output_data = str(request) + '\n'
    fp.write(output_data)
    s.sendall(request)
    # print("Request sent .....")
    # fname = "output_data/file_"+str(id)+".ts"
    vlen = mcl_receive_data(s, fname, fp)
    # port = s.getsockname()[1]
    # s.close()
    mcl_fclose(fp)
    return vlen


def mcl_send_socket_data(debug, s, data):
    s.sendall(data)
