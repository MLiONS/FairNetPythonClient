import socket
import time
import select
import ssl

def recv_data(sock):
    r, w, e = select.select([sock], [], [], 0.01)
    if r:
        data = s.recv(4096).decode('utf-8')
        print(str(data))

#webserver = "192.168.43.220"
webserver = "127.0.0.1"
#webserver = ''
#port = 44444
#port = 55556
#port = 8088
#port = 56088
port = 8084
# create a socket to connect to the web server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM,socket.IPPROTO_TCP)
#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
#s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect((webserver,port))
output_data = "Successfuly connected to webserver " + str(s) + '\n'
print(output_data)
ss = s
context = ssl.SSLContext(ssl.PROTOCOL_TLS) #Original TLSv1
context.load_cert_chain('../SSL_cert/1/server.cert', '../SSL_cert/1/server.key')
s = context.wrap_socket(ss, server_hostname="Vinod")
#time.sleep(5)
s.sendall("Hello\t".encode('utf-8'))
recv_data(s)
s.sendall("Vinod\t".encode('utf-8'))
recv_data(s)
s.sendall("Khandkar".encode('utf-8'))
recv_data(s)
s.close()
