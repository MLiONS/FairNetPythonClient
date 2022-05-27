from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import json   # module to parse JSON to dictionary
import sys, time
import threading
from threading import Thread
from scapy.all import sniff

caps = DesiredCapabilities.CHROME
caps['loggingPrefs'] = {'performance': 'ALL'}

options = webdriver.ChromeOptions()
options.add_experimental_option('w3c', False)

driver = webdriver.Chrome(desired_capabilities=caps, options=options)

check = threading.Event()
var=0


def mcl_download_media(debug, vid_link):
    global check
    global driver
    print("\nDownloader started")
    driver.get(vid_link)
    time.sleep(1)
    tl=((driver.find_element_by_class_name('ytp-time-duration')).text).split(':')
    #t_sleep = int(tl[0])*60 + int(tl[1]) + int(5)
    t_sleep = 45
    return t_sleep*3    

def sniffer(check):
    global var
    global driver
    print("Sniffing started \n")
    var=sniff(stop_filter=lambda x: check.is_set())
    logs=driver.get_log('performance')
    driver.quit()
    logreqs = [item for item in logs if 'Network.requestWillBeSent' in str(item)]

    file_http=open(file='HTTPlogs.txt', mode='w')

    for i in logreqs:
        tmp=json.loads(i['message'])
        if (tmp['message']['params']['request']['method']=='GET'):
            file_http.write('GET ' + tmp['message']['params']['request']['url']+' HTTP/1.1\n' )
            file_http.write('HOST: '+tmp['message']['params']['documentURL']+'\n')
            file_http.write('HEADERS: '+str(tmp['message']['params']['request']['headers'])+'\n\n')
            
    file_http.close()
    print("Sniffing Complete \n")


if __name__ == '__main__':
    print("Enter Video link")
    vid_link=str(input())
    t1=Thread(target = mcl_download_media, args=(vid_link, ))
    t2=Thread(target = sniffer, args=(check, ))
    t1.start()
    t2.start()
    t2.join()
    var.summary()
