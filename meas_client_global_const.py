# -*- coding : utf-8 -*-
from collections import namedtuple

clientId = "DESKTOP-CLIENT"
global proxy
# webserver = "10.119.2.18" # Raigad
webserver = 's3.ieor.iitb.ac.in'
# webserver = "10.119.21.43"
# webserver = '192.168.0.22'
# webserver = '192.168.43.220'
# webserver = '192.168.0.10'
# webserver = '192.168.0.12'
# webserver = "34.93.220.209"
# webserver = "34.89.43.57"
#webserver = "127.0.0.1"
# webserver = None
# webport = 80
webport = 8084
# proxy = "192.168.0.101"
# proxy = '192.168.0.19'
# proxy = 's3.ieor.iitb.ac.in'
# proxy = "34.93.220.209"
# proxy = '10.119.32.26'
# proxy = '10.119.21.90'
# proxy='192.168.225.118'
# proxy = '192.168.0.10'
# proxy = '10.119.21.11'
# proxy_port = 80
global proxy_port
# proxy_port = 443
# proxy_port = 8084
# use_proxy = 1
# RSV = 0 : No proxy using script from Original server
# RSV = 1 : Replay proxy
# RSV = 2 : Proxy using script from original server
# RSV = 3 : No proxy/vpn, no script
# RSV = 4 : With vpn, no script
# use_stored_data = 1
ESNI = False
DEBUG = 1
tout = 300
test_app = "YOUTUBE_1"
# app_list = ["SAAVN","SPOTIFY","WYNK","GAANA.COM","YOUTUBE","PRIMEVIDEO","NETFLIX","HOTSTAR"]
# app_list = {"YOUTUBE": {2, 3}} #, "YOUTUBE": {1}}
# app_list = {"YOUTUBE": {2}, "FILE": {2}}
app_list = {"HOTSTAR": {1}}
# app_list = {"YOUTUBE": {1}, "HOTSTAR": {1}, "NETFLIX": {1}, "PRIMEVIDEO": {1}}
# app_list = {"GAANA.COM": {1}, "PRIMEVIDEO": {1}, "WYNK": {1}}
# app_list = {"NETFLIX": {1,2,3,4,5,6,7,8,9}}
# app_list = {"SAAVN": {1}, "SPOTIFY": {1}, "WYNK": {1}, "GAANA.COM": {1}}
# app_list = {"NETFLIX": {0, 1, 2, 3, 4}}
# app_list = {"NETFLIX": {1}, "FILE": {1}}
# app_list = {"FILE": {1}}
# app_list = {"PRIMEVIDEO": {0}}
# app_list = ["SAAVN","SPOTIFY","WYNK","GAANA.COM"]
# app_list = {"PRIMEVIDEO","YOUTUBE","NETFLIX","HOTSTAR","SPOTIFY"}
# app_list = {}


app_data = {}
burst_data = {}
app_th = {}

th_max = {}
th_avg = {}
th_diff_h2l = []
th_per_app = {}

import threading
sniff_pkts = None
dl_ready = threading.Event()
dl_done = threading.Event()
sniff_done = threading.Event()

s_th = 0
num_installs = 0
installs = []
u_info = None

global user_name
user_name = None
global user_info
user_info = []
global user_result
user_result = []

MAX_DATA = 625000*10
MAX_SEG_DATA = 625000
MAX_NUM_PKTS = 15000
MIN_NUM_PKS = 100
b2b_http = 0
MAX_TD_THDIFF = 1000000
MAX_TD_CS = 5

dl_NETFLIX_done = threading.Event()
dl_HOTSTAR_done = threading.Event()
dl_YOUTUBE_done = threading.Event()
dl_PRIMEVIDEO_done = threading.Event()
dl_GAANACOM_done = threading.Event()
dl_SAAVN_done = threading.Event()
dl_SPOTIFY_done = threading.Event()
dl_WYNK_done = threading.Event()
dl_FILE_done = threading.Event()

global dl_ready_bmp
dl_ready_bmp = 0
global dl_status_bmp
dl_status_bmp = 0

from collections import defaultdict 
port_to_app_map = defaultdict(list)

sock_file_no = 0

app_to_ps_event_map = {"NETFLIX":dl_NETFLIX_done,
                       "HOTSTAR":dl_HOTSTAR_done,
                       "YOUTUBE":dl_YOUTUBE_done,
                       "PRIMEVIDEO":dl_PRIMEVIDEO_done,
                       "GAANA.COM":dl_GAANACOM_done,
                       "SAAVN":dl_SAAVN_done,
                       "SPOTIFY":dl_SPOTIFY_done,
                       "WYNK":dl_WYNK_done,
                       "FILE" : dl_FILE_done,
                       "": dl_done
                       }

app_to_color_map = {"NETFLIX_2": 'blue',
                    "HOTSTAR_2":"green",
                    "PRIMEVIDEO_2": 'red',
                    "YOUTUBE_2": 'purple',
                    "GAANA.COM_2": 'purple',
                    "SPOTIFY_2": 'magenta',
                    "SAAVN_2": 'blue',
                    "WYNK_2": 'green',
                    "NETFLIX_0": "green",
                    "HOTSTAR_0": 'red',
                    "PRIMEVIDEO_0": 'purple', 
                    "YOUTUBE_0": 'blue',
                    "GAANA.COM_0": 'magenta', 
                    "SPOTIFY_0": 'blue', 
                    "SAAVN_0": 'green',
                    "WYNK_0":  'purple',
                    "NETFLIX_1": 'red',
                    "HOTSTAR_1": 'purple',
                    "PRIMEVIDEO_1": 'blue',  
                    "YOUTUBE_1": 'green',
                    "GAANA.COM_1": 'green',
                    "GAANA_COM_1": 'green',
                    "SAAVN_1": 'purple',
                    "SPOTIFY_1": 'black',
                    "HUNGAMA_1": 'purple',
                    "WYNK_1": "magenta",
                    "NETFLIX_3": "green",
                    "HOTSTAR_3": 'red',
                    "PRIMEVIDEO_3": 'purple', 
                    "YOUTUBE_3": 'blue',
                    "GAANA.COM_3": 'magenta', 
                    "SPOTIFY_3": 'blue', 
                    "SAAVN_3": 'green',
                    "WYNK_3":  'purple',
                    "NETFLIX_4": 'purple',
                    "HOTSTAR_4": 'purple',
                    "PRIMEVIDEO_4": 'blue',  
                    "YOUTUBE_4": 'purple',
                    "GAANA.COM_4": 'blue',  
                    "SPOTIFY_4": 'green',  
                    "SAAVN_4": 'purple',
                    "WYNK_4": "magenta",
                    "YOUTUBE_5":"red",
                    "FILE_1": "red"
}


def mcl_sniff_var():
    global s_th
    global sniff_pkts
    s_th = None
    sniff_pkts = None


app_info = namedtuple("app_info", ["app", "param1", "param2"])
dinfo_struct = namedtuple("dinfo", ['dtime', 'dlen'])
import warnings
warnings.filterwarnings("ignore")

is_speed_test = False

nl_count = []
nl_ps = {}
min_num_ts = 10000

