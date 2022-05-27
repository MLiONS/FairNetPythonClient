import socket
import ssl

#addr = '127.0.0.1'
addr = ""
#port = 8088
port = 8084
MAX_CONN = 10

def recv_data(c):
    data = c.recv(4096)
    if None != data and "" != data:
        print(data.decode('utf-8'))
        c.sendall(data)

# Create socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
server_socket = s
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
output_data = "Servere Socket creation successful \n"
print(output_data)
# Bind socket
s.bind((addr, port))
output_data = "Server Socket binding successful on" + ' ' + str(addr) + ':' + str(port) + '\n'
print(output_data)
# Bind socket
# Configure socket to listen
s.listen(MAX_CONN)
c, addr = s.accept()
ss = c
context = ssl.SSLContext(ssl.PROTOCOL_TLS) #Original TLSv1
context.load_cert_chain('../SSL_cert/1/server.cert', '../SSL_cert/1/server.key')
c = context.wrap_socket(ss,server_side=True)
recv_data(c)
recv_data(c)
recv_data(c)
c.close()
