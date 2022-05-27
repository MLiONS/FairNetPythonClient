# -*- coding: utf-8 -*-
#lserver = 'http://10b9baff.ngrok.io'
#lserver = '52.15.194.28'
#lport = 80
#lserver = '116.73.123.101'
#lport = 50005
#lserver = 'www.vinodkhandkar.duckdns.org'
#lport = 27015
#lserver = "audio4-fa.scdn.co"
lserver = "https://www.google.com"
#lserver = "vodhls-vh.akamaihd.net"
#lserver = "10.119.2.18"
#lserver = "103.21.125.143"
lserver = "https://www.youtube.com"
lport = 443
with_proxy = 1
proxy_addr = "s3.ieor.iitb.ac.in"
proxy_port = 8084
import socket, ssl, struct

def mcl_proxy_version_command(sock):
    ver = 5
    nmethods = 1
    method = 0
    proxy_ver = struct.pack("!B",ver)
    nmethods =  struct.pack("!B",nmethods)
    proxy_ver = b''.join((proxy_ver,nmethods))
    method = struct.pack("!B",method)
    proxy_ver = b''.join((proxy_ver,method))
    #print(str(proxy_ver))
    sock.sendall(proxy_ver)
    #res = sock.recv(8192)
    ver = sock.recv(1)
    ver = struct.unpack("!B",ver)
    print("Version : "+str(ver))
    print("Version handshake done ...")

def mcl_proxy_connect_command(sock,rserver,rport):
    ver = 5
    cmd = 1 # CONNECT
    rsv = 0
    atyp = 3
    res = socket.getaddrinfo(rserver,rport,0,0,socket.IPPROTO_TCP)
    dst_addr = res[0][4][0]
    print("Webserver: "+str(dst_addr))
    dst_port = None
    proxy_ver = struct.pack("!B",ver)
    proxy_cmd = struct.pack("!B",cmd)
    proxy_rsv = struct.pack("!B",rsv)
    proxy_atyp = struct.pack("!B",atyp)
    #proxy_dst_addr = socket.inet_aton(dst_addr)
    pda = bytes(rserver,'utf-8')
    print("PDA : "+str(pda))
    pda_len = struct.pack("!B",len(pda))
    proxy_dst_addr = b''.join((pda_len,pda)) 
    print("Port: "+str(rport))
    proxy_dst_port = struct.pack("!H",rport)
    proxy_connect = b''.join((proxy_ver,proxy_cmd,proxy_rsv,proxy_atyp,proxy_dst_addr,proxy_dst_port))
    sock.sendall(proxy_connect)
    res = sock.recv(1)
    print(str(res)+'\n')
    res = struct.unpack("!B",res)
    print("Connect handshake is "+str(res[0]))

def mcl_conn_proxy_server(sproxy,sport,rserver,rport):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((sproxy, sport))
    print("Connected to proxy server ......")
    mcl_proxy_version_command(sock)
    mcl_proxy_connect_command(sock,rserver,rport)
    print("Opened Proxy tunnel ......")
    return sock

try:
    if with_proxy == 1:
        rserver = lserver.split("//")[1]
        print("LSERVER: "+str(lserver))
        s = mcl_conn_proxy_server(proxy_addr,proxy_port,rserver,lport)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        sock = context.wrap_socket(s, server_hostname=lserver)
        print("Connected .....")
    else:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, socket.IPPROTO_TCP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.5)
        s.connect((lserver,lport))
        print("Connected .....")
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        sock = context.wrap_socket(s, server_hostname=lserver)
        #sock.connect((lserver,lport))
    s.close()
    sock.close()
except Exception as e:
    output_data = "Unable to setup socket\n" + str(e)
    print(output_data)
    s.close()
    sock.close()
