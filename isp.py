
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17',
    'From': '123@gmail.com'  # This is another valid field
}


def get_opname(ipa):
    import requests
    import html
    isp_name = ipa
    url = "http://whatismyipaddress.com/ip/"
    url = url + str(ipa)
    # print("URL = "+str(url))
    response = requests.get(url, headers=headers)
    s = html.unescape(response.content.decode('utf-8'))
    s = s.split("\n")
    for line in s:
        if "ISP" in line:
            # print(line)
            isp_line = line
    isp_line = isp_line.split("</th><td>")[1].split("<")[0]
    print(isp_line)
    return isp_line


def send_isp_name(c, addr):
    ipaddr = addr[0]
    print("Ipaddr = "+str(ipaddr))
    opname = "Local ISP"#get_opname(ipaddr)
    print("Operator name = "+str(opname))
    c.sendall(opname.encode('utf-8'))


if __name__ == "__main__":
    ipaddr = ["116.72.168.254"]
    send_isp_name(None, ipaddr)
