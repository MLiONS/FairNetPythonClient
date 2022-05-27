# -*- coding: utf-8 -*-
import sys

from scapy.all import *
from meas_client_utils import mcl_fopen, mcl_fclose, mcl_fwrite, mcl_delete_file
from meas_client_global_const import MAX_DATA, b2b_http, \
    app_data, burst_data
import meas_client_global_const
import ssl

PORT = 443
TLS_VER = ssl.PROTOCOL_TLSv1_2


def mcl_get_http_headers(debug, app, typeid):
    # Zee5 HEADER
    z5_headers = "accept: */*\r\naccept-encoding: gzip, deflate, br\r\naccept-language: en-GB,en-US;q=0.9,en;q=0.8\r\norigin: https://www.zee5.com\r\nreferer: https://www.zee5.com/\r\nsec-ch-ua: Google Chrome;v=93, Not;A Brand;v=99, Chromium;v=93\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: macOS\r\nsec-fetch-dest: empty\r\nsec-fetch-mode: cors\r\nsec-fetch-site: cross-site\r\nuser-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    # HOTSTAR HEADER
    hs_headers = "Accept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: keep-alive\r\nHost: hssportsprepack.akamaized.net\r\nOrigin: https://www.hotstar.com\r\nReferer: https://www.hotstar.com/\r\nsec-ch-ua: Google Chrome;v=93, Not;A Brand;v=99, Chromium;v=93\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: macOS\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Site: cross-site\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    # hs_headers = "Host: gcloud.hotstar.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nTE: Trailers\r\n\r\n"
    # hs_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nHost: hses.akamaized.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\r\n"
    #hs_headers = "User-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    # YOUTUBE HEADER
    # yt_headers = "Host: r9---sn-ci5gup-cvhd.googlevideo.com\r\nConnection: keep-alive\r\nUser-agent: Mozilla/5.0 (Windows NT 10.0; -) Gecko/20100101 Firefox/66.0\r\nAccept: */*\r\ncache-control: max-age=0\r\nupgrade-insecure-requests: 1\r\n\r\n"
    yt_headers = "Connection: keep-alive\r\nUser-agent: Mozilla/5.0 (Windows NT 10.0; -) Gecko/20100101 Firefox/66.0\r\nAccept: */*\r\ncache-control: max-age=0\r\nupgrade-insecure-requests: 1\r\n\r\n"
    # Gaana.com Header
    gaana_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nCookie: _alid_=Q7W4WuFYau4djubYQujGqA==; hdntl=exp=1564350818~acl=%2fi%2fsongs%2f20%2f1855520%2f21250887%2f21250887_64.mp4%2f*~data=hdntl~hmac=eee41ca29a05f75d8f498f5bad222978e9a2cd51cdd6bbc4e3345999a486c219\r\nHost: vodhls-vh.akamaihd.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\r\n"
    # SPOTIFY Header
    sp_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n\r\n"
    # Saavn header
    sv_headers = "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\naccept-encoding: gzip, deflate, br\r\naccept-language: en-US,en;q=0.9\r\ncache-control: max-age=2\r\nupgrade-insecure-requests: 1\r\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\r\n"
    # Wynk Header
    wynk_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nCookie: _alid_=LEAWeSdl8QO8wBjtOrraWg==; hdntl=exp=1564347548~acl=*%2fsrch_tipsmusic%2fmusic%2f*%2f1467397498%2fsrch_tipsmusic_INT101303504.mp4.csmil*~data=hdntl~hmac=e4c76a2a21addd5930f1da8e522e67b745ba0fe791a07238cbd483fbd97f8c0e\r\nHost: desktopsecurehls-vh.akamaihd.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\r\n"
    # Hungama HEADER
    # hungama_headers = "Host: securehungama-vh.akamaihd.net\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0\r\nConnection: keep-alive\r\nCookie: _alid_=fSlNjk5a91E50fbRJHJvoA==\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    hungama_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nCookie: _ga=GA1.2.1616412296.1560728276; _gid=GA1.2.1221380282.1560728276; _fbp=fb.1.1560728276766.1081164596; PHPSESSID=edmksrtibgqmn8l0pdls1fsqt5; h_profile=%7B%22status%22%3A0%2C%22country_code%22%3A%22IN%22%7D; _hcntr=IN; _huid=180f8f84f48660ab2b2ca8c8689e749c; gig_hasGmid=ver2; __gads=ID=412ce9fdcae1512b:T=1560728276:S=ALNI_Mbv6hmoiVl20vbR0YrEVqLSLLI5Sg; halogin=180f8f84f48660ab2b2ca8c8689e749c; hcom_audio_qty=high; _gat=1\r\nHost: akdls3re.hungama.com\r\nRange: bytes=0-1048575\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36\r\n\r\n"
    # Google play header
    gp_headers = "Host: r2---sn-i5uif5t-cvhl.c.doc-0-0-sj.sj.googleusercontent.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    # Netflix headers
    nf_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n\r\n"
    # For Vodafone
    # nf_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nHost: ipv4-c017-bom001-ix.1.oca.nflxvideo.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n\r\n"
    # For Jio
    # nf_headers = "content-encoding: utf-8\r\nAccept: text/html\r\nAccept-Encoding: utf-8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nHost: ipv6-c007-bom001-jio-isp.1.oca.nflxvideo.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n\r\n"
    # For Airtel
    # nf_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nHost: ipv4-c002-bom001-bhartiairtel-isp.1.oca.nflxvideo.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n\r\n"
    # Prime Video Headers
    pv_headers = "HOST: s3-sin-ww.cf.dash.row.aiv-cdn.net\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36\r\n\r\n"
    pv_headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: keep-alive\r\nHost: wehe-data.ccs.neu.edu\r\nReferer: https://wehe-data.ccs.neu.edu/\r\nsec-ch-ua: Chromium;v=94, Google Chrome;v=94, ;Not A Brand;v=99\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: macOS\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36"

    app_to_headers_map = {
        "ZEE5": z5_headers,
        "HOTSTAR": hs_headers,
        "YOUTUBE": yt_headers,
        "PRIMEVIDEO": pv_headers,
        "GAANA.COM": gaana_headers,
        "SPOTIFY": sp_headers,
        "SAAVN": sv_headers,
        "WYNK": wynk_headers,
        "HUNGAMA": hungama_headers,
        "GOOGLEPLAY": gp_headers,
        "NETFLIX": nf_headers,
        "FILE": ""
    }
    headers = app_to_headers_map.get(app, None)
    return headers


def mcl_get_input_file_p(debug, app, typeid):
    app_to_file_map = {
        "ZEE5": "input_data/z5.rp",
        "HOTSTAR": "input_data/hs.rp",
        "YOUTUBE": "input_data/yt.rp",
        "NETFLIX": "input_data/nf.rp",
        "PRIMEVIDEO": "input_data/pv.rp",
        "GAANA.COM": "input_data/gc.rp",
        "SPOTIFY": "input_data/sp.rp",
        "SAAVN": "input_data/sv.rp",
        "WYNK": "input_data/wynk.rp",
        "HUNGAMA": "input_data/hungama.rp",
        "GOOGLEPLAY": "input_data/gp.rp",
        "FILE": "input_data/hs.rp"
    }
    app_to_file_org_map = {
        "HOTSTAR": "input_data/hs_org.rp",
        "YOUTUBE": "input_data/yt_org.rp",
        "ZEE5": "input_data/z5_org.rp",
        "NETFLIX": "input_data/nf_org.rp",
        "PRIMEVIDEO": "input_data/pv_org.rp",
        "GAANA.COM": "input_data/gc_org.rp",
        "SPOTIFY": "input_data/sp_org.rp",
        "SAAVN": "input_data/sv_org.rp",
        "WYNK": "input_data/wynk_org.rp",
        "HUNGAMA": "input_data/hungama_org.rp",
        "GOOGLEPLAY": "input_data/gp_org.rp",
        "FILE": "input_data/file_org.rp"
    }
    app_to_file_sto_map = {
        "HOTSTAR": "input_data/hs_sto.rp",
        "YOUTUBE": "input_data/yt_sto.rp",
        "ZEE5": "input_data/z5_sto.rp",
        "NETFLIX": "input_data/nf_sto.rp",
        "PRIMEVIDEO": "input_data/pv_sto.rp",
        "GAANA.COM": "input_data/gc_sto.rp",
        "SPOTIFY": "input_data/sp_sto.rp",
        "SAAVN": "input_data/sv_sto.rp",
        "WYNK": "input_data/wynk_sto.rp",
        "HUNGAMA": "input_data/hungama_sto.rp",
        "GOOGLEPLAY": "input_data/gp_sto.rp",
        "FILE": "input_data/file_sto.rp"
    }
    app_to_file_map = [app_to_file_org_map, app_to_file_sto_map, app_to_file_org_map]
    napp = app.split("_")[0]
    fname = app_to_file_map[typeid].get(app, "input_data/default.rp")
    # fname = app_to_file_map.get(app,"input_data/default.rp")
    rpf = mcl_fopen(debug, fname, "r", "NA")
    return rpf


def mcl_proxy_version_command(sock):
    ver = 5
    nmethods = 1
    method = 0
    proxy_ver = struct.pack("!B", ver)
    nmethods = struct.pack("!B", nmethods)
    proxy_ver = b''.join((proxy_ver, nmethods))
    method = struct.pack("!B", method)
    proxy_ver = b''.join((proxy_ver, method))
    # print(str(proxy_ver))
    sock.sendall(proxy_ver)
    res = sock.recv(8192)
    print("Version Command successful")


def mcl_proxy_connect_command(sock, rserver, rport, app, typeid):
    from meas_client_global_const import app_list
    ver = 5
    cmd = 1  # CONNECT
    rsv = int(typeid)  # int(app_list[app]) #int(use_stored_data)
    print("RSV = " + str(rsv))
    atyp = 3
    proxy_ver = struct.pack("!B", ver)
    proxy_cmd = struct.pack("!B", cmd)
    proxy_rsv = struct.pack("!B", rsv)
    proxy_atyp = struct.pack("!B", atyp)
    # res = socket.getaddrinfo(rserver,rport,0,0,socket.IPPROTO_TCP)
    # dst_addr = res[0][4][0]
    # print("Webserver: "+str(dst_addr))
    # proxy_dst_addr_len = struct.pack("!B",len(dst_addr))
    # proxy_dst_addr =  proxy_dst_addr_len
    # proxy_dst_addr = None
    # for i in range (len(proxy_dst_addr)):
    #    tmp = struct.pack("!B", dst_addr[i])
    #    if None == proxy_dst_addr:
    #        proxy_dst_addr = tmp
    #    else:
    #        tmp = b''.join(( proxy_dst_addr,tmp))
    #    proxy_dst_addr = tmp
    # proxy_dst_addr = socket.inet_aton(dst_addr)
    pda = bytes(rserver, 'utf-8')
    # print("PDA : "+str(pda))
    pda_len = struct.pack("!B", len(pda))
    proxy_dst_addr = b''.join((pda_len, pda))
    # print("Port: "+str(rport))
    proxy_dst_port = struct.pack("!H", rport)
    proxy_connect = b''.join((proxy_ver, proxy_cmd, proxy_rsv, proxy_atyp, proxy_dst_addr, proxy_dst_port))
    sock.sendall(proxy_connect)
    res = sock.recv(8192)


def mcl_conn_proxy_server(sproxy, sport, rserver, rport, app, typeid):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to " + str(sproxy) + " : " + str(sport))
    sock.connect((sproxy, sport))
    if typeid != 1:
        print("Initiating SOCKSv5 handshake")
        mcl_proxy_version_command(sock)
        mcl_proxy_connect_command(sock, rserver, rport, app, typeid)
    print("Successfully connected to proxy server...")
    return sock


def mcl_conn_ssl_socket_proxy(sproxy, sport, rserver, rport, app, typeid):
    import socket, ssl
    output_data = "Using proxy at " + str(proxy) + ' ' + str(sport)
    print(output_data)
    output_data = "Connecting to " + str(rserver) + ' ' + str(rport)
    print(output_data)
    sock = mcl_conn_proxy_server(sproxy, sport, rserver, rport, app, typeid)
    s = sock
    port = sock.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # Original TLSv1
    s = context.wrap_socket(sock, server_hostname=rserver)
    port = s.getsockname()[1]
    print("Port: " + str(port) + " Server:" + str(s.getsockname()[0]))
    return s, port


def mcl_conn_ssl_socket_proxy_sd(sproxy, sport, rserver, rport, app, typeid):
    import socket, ssl
    mcl_ssl_cert_map = {
        "HOTSTAR": '../SSL_cert/server.cert',
        "YOUTUBE": '../SSL_cert/server.cert',
        "ZEE5": '../SSL_cert/server.cert',
        "PRIMEVIDEO": '../SSL_cert/server.cert',
        "NETFLIX": '../SSL_cert/server.cert',
        "GAANA.COM": '../SSL_cert/server.cert',
        "SPOTIFY": '../SSL_cert/server.cert',
        "SAAVN": '../SSL_cert/server.cert',
        "WYNK": '../SSL_cert/server.cert',
        "HUNGAMA": '../SSL_cert/server.cert',
        "GOOGLEPLAY": '../SSL_cert/server.cert'
    }
    mcl_app_sni_map = {
        "HOTSTAR": 'gcloud.hotstar.com',
        #"HOTSTAR": None,
        "NETFLIX": 'ipv4-c017-bom001-jio-isp.1.oca.nflxvideo.net',
        "YOUTUBE": 'r5---sn-cvh76ned.googlevideo.com',
        #"YOUTUBE": None,
        "PRIMEVIDEO": 's3-sin-ww.cf.dash.row.aiv-cdn.net',
        "MXPLAYER": 'media-content.akamaized.net',
        "ZEE5": 'z5ams.akamaized.net',
        "VOOT": 'vootvideo.akamaized.net',
        "EROSNOW": 'tvshowhls-b.erosnow.com',
        "SONYLIV": 'securetoken.sonyliv.com',
        "WYNK": 'desktopsecurehls-vh.akamaihd.net',
        "GAANA.COM": 'vodhls-vh.akamaihd.net',
        "SAAVN": 'aa.cf.saavncdn.com',
        "SPOTIFY": 'audio4-fa.scdn.co',
        "PRIMEMUSIC": 'dfqzuzzcqflbd.cloudfront.net'
    }
    output_data = "Using proxy at " + str(proxy) + ' ' + str(sport)
    print(output_data)
    # output_data = "Connecting to " + str(rserver) + ' ' + str(rport)
    # print(output_data)
    sock = mcl_conn_proxy_server(sproxy, sport, rserver, rport, app, typeid)
    # sock.settimeout(0.5)
    s = sock
    port = sock.getsockname()[1]
    print("Port = " + str(sport))
    if sport != 80:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Original TLSv1
        serv_cert = mcl_ssl_cert_map.get(app, '../SSL_cert/server.cert')
        print(serv_cert)
        # context.check_hostname = False
        # context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain('../SSL_cert/server.cert', '../SSL_cert/server.key')
        context.load_cert_chain(serv_cert, '../SSL_cert/server.key')
        sni = mcl_app_sni_map.get(app, "")
        #sni = None
        if None is sni:
            s = context.wrap_socket(sock)
        else:
            if meas_client_global_const.ESNI:
                s = context.wrap_socket(sock)
                sock = s
            s = context.wrap_socket(sock, server_hostname=sni)
        # s = context.wrap_socket(sock)
        # s = context.wrap_socket(sock, server_hostname="ipv4-c017-bom001-jio-isp.1.oca.net.XYZZ")
    port = s.getsockname()[1]
    print("Local Port: " + str(port) + " Local address:" + str(s.getsockname()[0]))
    return s, port


def mcl_conn_ssl_socket(HOST, PORT):
    import socket, ssl
    print(str(HOST) + ' ' + str(PORT))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, socket.IPPROTO_TCP)
    sock.connect((HOST, PORT))
    # Get socket without SNI
    # print("Socket without SNI")
    # sock = mcl_get_ini_ssl_socket(sock, (HOST, PORT))
    # s = sock
    # Update socket with correct SNI
    # print("Socket without SNI")
    #hostname = "x" + HOST + "xxxxx"
    #HOST = hostname
    print("HOSTNAME : " + str(HOST))
    context = ssl.SSLContext(TLS_VER)  # Original TLSv1
    context.verify_mode = ssl.CERT_NONE
    s = context.wrap_socket(sock, server_side=False)
    # s = context.wrap_socket(sock, server_side=False, server_hostname=HOST)
    # s.connect((HOST, PORT))
    port = s.getsockname()[1]
    print("Port: " + str(port) + " Server:" + str(s.getsockname()[0]))
    return s, port


def mcl_get_host_from_url(url):
    return url.split('/')[2]


def mcl_extract_info_from_url(url):
    host = mcl_get_host_from_url(url)
    file = url.split(host)[1]
    return host, file


def mcl_format_http_get(headers, host, file):
    request = "GET " + file + " HTTP/1.1\r\nHOST: " + host + "\r\n"
    sparam = "SPEED:3"
    request = request + headers + sparam
    return request.encode()


def mcl_get_download_info(headers, url, fp):
    import socket, sys
    host, file = mcl_extract_info_from_url(url)
    output_data = "HOST:" + host + '\n'
    # print(output_data)
    # fp.write(output_data)
    output_data = "FILE:" + file + '\n'
    # fp.write(output_data)
    request = mcl_format_http_get(headers, host, file)
    output_data = "REQUEST+HEADER:" + str(request) + '\n'
    # fp.write(output_data)
    return host, request


def mcl_get_socket(host, fp, app, typeid):
    global proxy
    proxy = meas_client_global_const.proxy
    if meas_client_global_const.proxy_port is not None:
        proxy_port = int(meas_client_global_const.proxy_port)
    else:
        proxy_port = None
    s = None
    port = None
    pstatus = typeid  # app_list[app]
    print("PSTATUS = " + str(pstatus))
    print("AppServer = " + str(proxy))
    # x = input()
    if pstatus == 0:
        s, port = mcl_conn_ssl_socket(host, PORT)
        port = s.getsockname()[1]
    elif pstatus == 1 or pstatus == 3:
        s, port = mcl_conn_ssl_socket_proxy_sd(proxy, proxy_port, host, PORT, app, typeid)
    elif pstatus == 2:
        s, port = mcl_conn_ssl_socket_proxy(proxy, proxy_port, host, PORT, app, typeid)
    output_data = "SSL SOCKET:" + str(s) + '\n'
    fp.write(output_data)
    return s, port


def mcl_form_initial_http_req(app):
    mcl_app_rserver_map = {"ZEE5": "https://zee5.com",
                           "NETFLIX": "https://www.netflix.com/",
                           "HOTSTAR": "https://www.hotstar.com/",
                           "YOUTUBE": "https://www.youtube.com/",
                           "PRIMEVIDEO": "https://www.primevideo.com/",
                           "GAANA.COM": "https://gaana.com/",
                           "SAAVN": "https://www.jiosaavn.com/",
                           "SPOTIFY": "https://www.spotify.com/",
                           "WYNK": "https://wynk.in/music",
                           "FILE": "https://www.thinkbroadband.com/",
                           "": None
                           }
    rserver = mcl_app_rserver_map.get(app)
    print("APP:" + str(app) + " SERVER: " + str(rserver))
    request = "GET " + rserver + " HTTP/1.1\r\n"
    print(request)
    return request.encode()


def mcl_form_dummy_http_req(data):
    request = "GET " + data + " HTTP/1.1\r\n"
    print(request)
    return request.encode()


def mcl_form_http_requests(debug, app, headers, typeid):
    lrequests = []
    fname = "output_data/dl_test" + str(app) + "_" + str(typeid) + ".txt"
    fp = mcl_fopen(debug, fname, "a", "DELETE")
    rpf = mcl_get_input_file_p(debug, app, typeid)
    line = "START"
    while '' != line:
        if "START" == line:
            line = rpf.readline()
            continue
        url = line.rstrip('\n')
        # print("URL:"+url)
        host, request = mcl_get_download_info(headers, url, fp)
        output_data = "HOST: " + str(host) + ' ' + "REQ: " + str(request) + '\n'
        # mcl_fwrite(debug,fp,output_data)
        lrequests.append(request)
        line = rpf.readline()
    output_data = str(lrequests) + '\n'
    mcl_fwrite(debug, fp, output_data)
    fp.close()
    rpf.close()
    return lrequests


def mcl_form_final_http_req():
    request = "GET END" + " HTTP/1.1\r\n"
    print(request)
    return request.encode("utf-8")


def mcl_change_sni(s, host, ofile, lrequests,
                   fname, fp, app, p_app_data, b_app_data, client_time):
    import ssl
    debug = 0
    from meas_client_internet import mcl_send_socket_data, mcl_receive_data, mcl_receive_socket
    for request in lrequests:
        try:
            # print("Sending: "+str(request))
            f = open(ofile, 'ab')
            f.write(request)
            f.close()
            mcl_send_socket_data(debug, s, request)
        except KeyboardInterrupt:
            output_data = "\n Application exiting due to user interruption\n"
            s.close()
    print("\n Waiting for OK from server\n ")
    rlen, p_app_data, b_app_data = mcl_receive_data(s, fname, fp, app, p_app_data, b_app_data, client_time)
    f = open(ofile, 'ab')
    output_data = "\n Initial data exchange done \n"
    print(output_data)
    f.write(output_data.encode())
    f.close()
    #s.server_hostname = host
    #s.do_handshake()
    #s.unwrap()
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    #mycipher = "DHE-RSA-AES128-SHA"
    #context.set_ciphers(mycipher)
    s = context.wrap_socket(s, server_hostname=host, server_side=False)
    return s


def mcl_start_download(debug, app, typeid):
    import time
    from datetime import datetime
    from meas_client_internet import mcl_send_socket_data, mcl_receive_data, mcl_receive_socket
    global proxy
    proxy = meas_client_global_const.proxy
    fname = "output_data/dl_test" + str(app) + "_" + str(typeid) + ".txt"
    fp = mcl_fopen(debug, fname, "a", "DELETE")
    fname = "output_data/" + str(app) + "_" + str(typeid)
    mcl_delete_file(fname)
    rpf = mcl_get_input_file_p(debug, app, typeid)
    print(str(typeid) + " : " + str(rpf))
    # return 0
    line = rpf.readline()
    url = line.rstrip('\n')
    headers = mcl_get_http_headers(debug, app, typeid)
    output_data = str(headers)
    mcl_fwrite(debug, fp, output_data)
    host, request = mcl_get_download_info(headers, url, fp)
    s, port = mcl_get_socket(host, fp, app, typeid)
    output_data = "PORT: " + str(port) + '\n'
    mcl_fwrite(debug, fp, output_data)
    mcl_fclose(fp)
    if False:
        rpf.close()
    data_len = 0
    output_data = 0
    dlen = 0
    # vcount = 0
    pcount = 0
    pth = []
    pindex = []
    th = 0
    # print("Line : "+str(line))
    lrequests = mcl_form_http_requests(debug, app, headers, typeid)
    # while '' != line:
    pe_key = str(app) + "_" + str(typeid)
    # ps_event = app_to_ps_event_map[ps_key]#app]
    # time.sleep(30)
    p_app_data = []
    b_app_data = []
    data = None

    if typeid == 1 or typeid == 3:
        dummy_map = {
            "HOTSTAR": 1,
            "YOUTUBE": 2,
        }
        print("Sending initial http req for stored data")
        request = mcl_form_initial_http_req(app)
        mcl_send_socket_data(debug, s, request)
        # request = mcl_form_dummy_http_req("XYZ")
        # print(request)
        # mcl_send_socket_data(debug, s, request)
        while "OK" != data:
            print("Waiting for OK from server")
            data = str(mcl_receive_socket(s).decode("UTF-8")).replace("\'","")
            print("Response received = " + str(data))

    time.sleep(1)
    client_time = datetime.now()
    print("Client sending time =" + str(client_time))

    # Change SNI
    #if typeid == 0:
    #    dfname = "output_data/dl_test" + str(app) + "_" + str(typeid) + ".txt"
    #    fp = mcl_fopen(debug, dfname, "a", "NA")
    #    s = mcl_change_sni(s, host, fname, lrequests.copy(), fname, fp, app, p_app_data, b_app_data, client_time)
    #    fp.close()
    #    time.sleep(1)

    num_req = 0
    for request in lrequests:
        try:
            num_req += 1
            print(str(app) + " : Request number : " + str(num_req))
            # print("Sending: "+str(request))
            mcl_send_socket_data(debug, s, request)
            if b2b_http == 0:
                dfname = "output_data/dl_test" + str(app) + "_" + str(typeid) + ".txt"
                fp = mcl_fopen(debug, dfname, "a", "NA")
                # pcount = 1
                # fname = "output_data/"+str(app)
                # fname = "output_data/"+str(app)+"_"+str(pcount)
                s.settimeout(30000)
                # print("Client sending time =" + str(client_time))
                rlen, p_app_data, b_app_data = mcl_receive_data(s, fname, fp, app, p_app_data, b_app_data, client_time)
                client_time = "INVALID_TIME"
                data_len += rlen
                # print("Data received = " + str(rlen))
                # print("Total download = " + str(data_len))
                if data_len > MAX_DATA:
                    # print("Final Total download = " + str(data_len) + " : " + str(MAX_DATA))
                    break
        except KeyboardInterrupt:
            output_data = "\n Application exiting due to user interruption\n"
            s.close()
            mcl_fclose(rpf)
            mcl_fclose(fp)
            print("Total Download : " + str(data_len))
            ps_event.set()
            # dl_done.set()
            return port

    if b2b_http == 1:
        while data_len < MAX_DATA:
            pcount = 1
            fname = "output_data/" + str(app) + "_" + str(typeid)
            # fname = "output_data/"+str(app)+"_"+str(pcount)
            s.settimeout(30000)
            dfname = "output_data/dl_test" + str(app) + "_" + str(typeid) + ".txt"
            fp = mcl_fopen(debug, dfname, "a", "NA")
            rlen = mcl_receive_data(s, fname, fp, app, p_app_data)
            data_len += rlen

    app_data[pe_key] = p_app_data
    burst_data[pe_key] = b_app_data
    request = mcl_form_final_http_req()
    mcl_send_socket_data(debug, s, request)
    s.close()
    mcl_fclose(rpf)
    mcl_fclose(fp)
    print("Total Download : " + str(data_len))
    # dl_done.set()
    # ps_event.set()
    fname = "output_data/port" + str(app) + "_" + str(typeid) + ".txt"
    fp = mcl_fopen(debug, fname, "a", "DELETE")
    output_data = str(port)
    mcl_fwrite(debug, fp, output_data)
    return port


def mcl_downloader_main():
    debug = 1
    app = "SPOTIFY"
    port = mcl_start_download(debug, app)
    print(port)
    # print("S_TH="+str(s_th))


if __name__ == '__main__':
    mcl_downloader_main()
