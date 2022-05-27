# -*- coding: utf-8 -*-
"""
Created on Tue Oct 31 02:54:48 2019

@author: khandkar
Version:
    0.1 : 05-03-2020 : Web server
"""
__spec__ = None

DEBUG = "ON" 
ERROR = "ERROR"
SUCCESS = "SUCCESS"
IGNORE = "IGNORE"

BUFF_SIZE = 8192 * 4

# appservif_addr = "10.119.21.43"
# appservif_addr = "192.168.0.19"
appservif_addr = "35.244.57.199"
appservif_port = 80

#INDIA_APPSERVER = "35.200.160.204"
#EUROPE_APPSERVER = "34.89.43.57"

#INDIA_APPSERVER = "13.234.54.36" #AWS
#EUROPE_APPSERVER = "3.9.3.217" #AWS
#APPSERVER_PORT = 443

#INDIA_APPSERVER = "192.168.0.13"
INDIA_APPSERVER = "127.0.0.1"
EUROPE_APPSERVER = "127.0.0.1"
APPSERVER_PORT = 8086

gloc_to_aserver_map = {"AFRICA":INDIA_APPSERVER,
        "AMERICA":EUROPE_APPSERVER,
        "ASIA":INDIA_APPSERVER,
        "AUSTRALIA":INDIA_APPSERVER,
        "EUROPE":EUROPE_APPSERVER}

def ws_get_ssl_client_socket(sock, rserver):
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Original TLSv1
    context.load_cert_chain('../SSL_cert/server.cert', '../SSL_cert/server.key')
    s = context.wrap_socket(sock, server_hostname=rserver)
    return s


def ws_get_appserver_info(gloc):
    status = "RUNNING"
    # server = "35.200.160.204"
    # server = "34.89.43.57"
    server = gloc_to_aserver_map[gloc]
    port = APPSERVER_PORT
    return status, server, port


def ws_get_appserver_info_old():
    import select
    import socket
    timeout = 1
    app_server = "0.0.0.0"
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Upgrade to SSL
    s = ws_get_ssl_client_socket(s, appservif_addr)
    # Connect to Webserver
    s.connect((appservif_addr, appservif_port))
    # Send request to appserver
    print("Connected to app server")
    comm = "REQUEST"
    sdata = comm.encode('utf-8')
    s.sendall(sdata)
    # Wait for response from appserver
    while True:
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = "SUCCESS"
                        break
                except KeyboardInterrupt:
                    rstatus = "ERROR"
                    break
            print("r: " + str(rs))
            print("w: " + str(ws))
            print("e: " + str(es))
            if rstatus == "SUCCESS":
                rdata = s.recv(BUFF_SIZE).decode('utf-8')
                print(rdata)
                rdata = rdata.split("\r\n")
                status = rdata[0]
                if "RUNNING" == status:
                    app_server = rdata[1]
                    app_port = rdata[2]
                    print("App server = " + str(app_server) + ":" + str(app_port))
                    break
            else:
                break
        except KeyboardInterrupt:
            rstatus = "ERROR"
            break
    # Extract app_server
    return status, app_server, app_port


def ws_inform_client(status, app_addr, port, c):
    IN_PORT = 80
    # Send status and application address to client
    sdata = status + "\r\n" + app_addr + "\r\n" + str(port) + "\r\n" + str(IN_PORT)
    print("Info from app server : "+str(sdata))
    sdata = sdata.encode('utf-8')
    c.sendall(sdata)

def ws_get_ssl_server_socket(c):
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS) #Original TLSv1
    context.load_cert_chain('../SSL_cert/server.cert', '../SSL_cert/server.key')
    ss = context.wrap_socket(c,server_side=True)
    return ss 

def mcl_store_report(report):
    import re
    import os
    m = re.search("ClientId:((\w+-)+\w+)", str(report), re.IGNORECASE)
    fname = m.group(1) + "-"
    m = re.search("Instance:(\d+[+]\d+)", str(report), re.IGNORECASE)
    pat = m.group(1)
    fname += pat
    fname = "Report/"+fname
    print(fname)
    if os.path.exists(fname):
        os.remove(fname)
    fp = open(fname,"a")
    fp.write(report)
    fp.close()


def mcl_receive_report(data, c):
    import os
    report = data
    if "Instance" not in report:
        while True:
            data = c.recv(BUFF_SIZE)
            data = data.decode('utf-8')
            #data = str(data)
            report += data
            if "Instance" in data:
                break;
    # print(report)
    mcl_store_report(report)
    print("Complete Report received ")


headers1 = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17',
    'Host': 'ip-api.com',
    'upgrade-insecure-requests': '1'
}


headers = {
'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
'cache-control': 'max-age=0',
'cookie': '__cfduid=d220433710cbe3b7ea934141e316789101609230405; cf_clearance=526e887b06aedb61cf9f64d1f52b8cc792555c36-1609230411-0-150; pt=9770307a99f8d37463e810c267d727aa; __qca=P0-1154940144-1609230412339; _ga=GA1.2.1446024302.1609230415; _gid=GA1.2.746546459.1609230415; fsbotchecked=true; _fsloc=?i=IN&c=Hyderabad&s=TG; _fssid=4eaae85b-e26c-46e4-add7-8b6d616a165f; fssts=false; __gads=ID=0663b6447de87bda:T=1609230419:S=ALNI_MZ2eqsQ9c_Ww6slx737S9QHNlNU0g; __utma=53830638.1446024302.1609230415.1609230735.1609230735.1; __utmc=53830638; __utmz=53830638.1609230735.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); __utmt_gwo=1; __utmb=53830638.1.10.1609230735; _omappvp=LXmJRPb0c4wUrJFlUftSUYMwh87PeQdGulpEocuY0dRi2P43ruNp0NKygZF91MOdgW3GG6AE8y0ox82YyZodvCEU3n6zt25b; _omappvs=1609230736671',
'sec-ch-ua': '"Google Chrome";v="87", " Not;A Brand";v="99", "Chromium";v="87"',
'sec-ch-ua-mobile': '?0',
'sec-fetch-dest': 'document',
'sec-fetch-mode': 'navigate',
'sec-fetch-site': 'none',
'sec-fetch-user': '?1',
'upgrade-insecure-requests': '1',
'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
}


def ws_get_opname_ipinfo(ipa):
    import requests
    isp_name = ipa
    url="http://ip-api.com/json/"
    url = url + str(ipa)
    print("URL : " + str(url))
    response = requests.get(url, headers=headers1)
    print("URL Response = "+str(response.text))
    response = response.text.split(",")[10]
    print("URL Response split = "+str(response))
    isp_name = response.split(":")[1].replace("\"", "")
    print("Response split : " + str(isp_name))
    print(isp_name)
    return isp_name


def ws_get_opname(ipa):
    import requests
    import html
    isp_name = ipa
    #url = "https://whatismyipaddress.com/ip/"
    url="http://ip-api.com/json/"
    url = url + str(ipa)
    print("URL : " + str(url))
    response = requests.get(url, headers=headers1)
    print("URL Response = "+str(response.text))
    s = html.unescape(response.content.decode('utf-8'))
    s = s.split("\n")
    for line in s:
        if "isp" in line:
            # print(line)
            isp_line = line
    isp_line = isp_line.split("</th><td>")[1].split("<")[0]
    print(isp_line)
    return isp_line


def ws_send_isp_name(c, addr):
    ipaddr = addr[0]
    ipaddr = "115.98.232.239"
    print("Ipaddr = "+str(ipaddr))
    opname = "local"
    #opname = ws_get_opname_ipinfo(ipaddr)
    print("Operator name = "+str(opname))
    c.sendall(opname.encode('utf-8'))


def ws_send_ipaddr (c, addr):
    ipaddr = addr[0]
    ipaddr = "60.254.0.52"
    print("Ipaddr = "+str(ipaddr))
    c.sendall(ipaddr.encode('utf-8'))


def ws_start_client_thread(c, addr):
    import select
    timeout = 1
    # Upgrade connection to SSL-connection
    c = ws_get_ssl_server_socket(c)
    while True:
        try:
            while True:
                try:
                    rs, ws, es = select.select([c], [], [], timeout)
                    if c in rs:
                        rstatus = "SUCCESS"
                        break
                except KeyboardInterrupt:
                    rstatus = "ERROR"
                    break
            print("r: " + str(rs))
            print("w: " + str(ws))
            print("e: " + str(es))
            if rstatus == "SUCCESS":
                # print("Socket data detected for read")
                data = ""
                while "" == data:
                    data = c.recv(BUFF_SIZE)
                    data = data.decode('utf-8')
                print("Received data = " + str(data))
                break
            else:
                break
        except KeyboardInterrupt:
            rstatus = "ERROR"
            break
    # Get the clientId from client
    #data = c.recv(BUFF_SIZE)
    #data = data.decode('utf-8')
    #print("Received = "+str(data))
    if "IPADDR" in data:
        print("Received = "+str(data))
        # ws_send_isp_name(c, addr)
        ws_send_ipaddr(c, addr)
    elif "REPORT" in data:
        print("Report found")
        # data = data1.decode('utf-8')
        mcl_receive_report(data, c)
    else:
        print("ClientId = " + str(data))
        # inform application server about the client
        # and Get the permission
        print("Contacting application server ")
        gloc = data.split(":")[1]
        status, app_addr, port = ws_get_appserver_info(gloc)
        # Provide application server address to client
        ws_inform_client(status, app_addr, port, c)


def ws_accept_client(s):
    import threading
    import select
    import socket
    import math
    rstatus = ERROR
    timeout = 1
    # a forever loop until we interrupt it or  
    # an error occurs 
    output_data = "[+]Waiting for client to connect \n"
    print(output_data)
    # For Testing 
    # status, app_addr, port = ws_get_appserver_info()
    while True:
        # Establish connection with client. 
        try:
            while True:
                try:
                    rs, ws, es = select.select([s], [], [], timeout)
                    if s in rs:
                        rstatus = SUCCESS
                        break
                except KeyboardInterrupt:
                    rstatus = ERROR
                    break
            print("r: "+str(rs))
            print("w: "+str(ws))
            print("e: "+str(es))
            if rstatus == SUCCESS:
                c, addr = s.accept()
                print("Client accepted..")
                c2s = threading.Thread(target=ws_start_client_thread, args=(c, addr, ))
                c2s.start()
            else:
                break
        except KeyboardInterrupt:
            if server_socket != None:
                server_socket.close()
            rstatus = ERROR
            break
    return rstatus


def ws_setup_sserver(port, addr):
    import socket
    MAX_CONN = 10000000
    rstatus = ERROR
    s = None
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        server_socket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        output_data = "Client Side Socket creation successful \n"
        print(output_data)
        # Bind socket
        s.bind((addr, port))
        output_data = "Client Side Socket binding successful on" + ' ' + str(addr) + ':' + str(port) + '\n'
        print(output_data)
        # Bind socket
        # Configure socket to listen
        s.listen(MAX_CONN)
        output_data = "Client Side Socket listening \n"
        print(output_data)
        rstatus = SUCCESS
        output_data = "[+] Successfully setup FairNet App web server [" + str(port) + "]" + '\n'
        print(output_data)
    except Exception as e:
        output_data = "Unable to setup socket\n" + str(e)
        print(output_data)
        rstatus = ERROR
    return rstatus, s


def webserver(port, addr):
    import os
    s = None
    try:
        rstatus, s = ws_setup_sserver(port, addr)
        if ERROR == rstatus:
            output_data = "Exiting due to server socket error 1\n"
            print(output_data)
            return rstatus
        while 1:
            rstatus = ws_accept_client(s)
            if ERROR == rstatus:
                output_data = "sserver:1:Exiting due to error\n"
                if s:
                    s.close()
                return rstatus
    except KeyboardInterrupt:
        if s:
            s.close()
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
    return rstatus


def webserver_main(port, addr):
    rstatus = ERROR
    try:
        rstatus = webserver(port, addr)
    except KeyboardInterrupt:
        output_data = "\n Application exiting due to user interruption\n"
        rstatus = ERROR
        return rstatus


if __name__ == '__main__':
    lport = 8084
    laddr = ''
    webserver_main(lport, laddr)
