import socket
import time
import os
import threading
import struct
import base64
from urlparse import urlparse

port = 20100
buf_sz = 261244

url_count = {}
url_time = {}
cache_key = {}
cache_time = {}
cache_modified_time = {}
BLACKLIST_FILE = "proxy/blacklist.txt"
AUTHENTICATION_FILE = "proxy/authentication.txt"
ADMINS_FILE = "proxy/admin.txt"
cache = ["", "", ""]


class Server:
    def __init__(self):
        self.socket_first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_first.bind(("", port))
        self.socket_first.listen(10)
        self.__clients = {}
        self.cache_cur = 0

    def beg_thread(self):
        # if os.path.isdir("./cache") == False:
        # 	os.makedirs("./cache")
        while True:
            (clientSocket, addr) = self.socket_first.accept()
            begs = (clientSocket, addr)
            thread_t = threading.Thread(
                target=self.proxy_func_thread, args=begs)
            thread_t.setDaemon(True)
            thread_t.start()

    def check_blocked_site(self, ip_addr):
        given_ip = struct.unpack('>I', socket.inet_aton(ip_addr))[0]
        try:
            f = open(BLACKLIST_FILE, "r")
        except:
            return False
        data = f.read().splitlines()
        for el in data:
            (ip, cidr) = el.split('/')
            host_bits = 32 - int(cidr)
            i = struct.unpack('>I', socket.inet_aton(ip))[0]
            start = (i >> host_bits) << host_bits
            end = start | ((1 << host_bits) - 1)
            if given_ip >= start and given_ip <= end:
                return True
        return False

    def isBlocked(self, ip_addr, auth):
        # user not valid 1
        # user valid, not admin, blocked : 2
        # user valid, not blocked : 3
        # user valid, admin, blocked : 3
        is_authen, is_admin = False, False
        is_blocked_site = False
        if auth in user_auths:
            is_authen = True
        if auth in admin_auths:
            is_admin = True
        is_blocked_site = self.check_blocked_site(ip_addr)
        if is_authen == False and is_admin == False:
            return 1
        if is_blocked_site == False:
            return 3
        if is_blocked_site == True and is_admin == False:
            return 2
        if is_blocked_site == True and is_admin == True:
            return 3
        return 3

    def proxy_func_thread(self, conn, addr):
        request = conn.recv(buf_sz)
        if request[:7] == 'CONNECT':
            exit(0)
        print request
        tempo = request.splitlines()
        first_line = request.split('\n')[0]
        auth = tempo[2].split(' ')[2]
        try:
            url = first_line.split(' ')[1]
        except:
            exit(0)
        try:
            if_modified_since = request.split('\n')[10]
        except:
            if_modified_since = ""
        if if_modified_since[:17] != 'If-Modified-Since':
            if_modified_since = ""
        else:
            if_modified_since = if_modified_since[19:]

        http_position = url.find("://")
        if (http_position == -1):
            port_url = url
        else:
            port_url = url[(http_position+3):]

        if http_position != -1:
            if url in url_count.keys():
                url_count[url] += 1
                if time.time() - url_time[url] > 300:
                    url_count[url] = 1
                    url_time[url] = time.time()
            else:
                url_count[url] = 1
                url_time[url] = time.time()

        for i in url_time.keys():
            if time.time() - url_time[i] > 300 and url_count[i] > 0:
                url_count[i] = 0
                del url_count[i]
                del url_time[i]

        port_pos = port_url.find(":")
        webserver_pos = port_url.find("/")
        if webserver_pos == -1:
            webserver_pos = len(port_url)
        webserver = ""
        port = -1
        if (port_pos == -1 or webserver_pos < port_pos):
            port = 80
            webserver = port_url[:webserver_pos]
        else:
            port = int((port_url[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = port_url[:port_pos]
        print webserver
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(50)

        given_ip = socket.gethostbyname(webserver)
        print given_ip
        auth_type = self.isBlocked(given_ip, auth)
        if auth_type == 1:
            conn.send('User Authentication Failed for this connection')
            exit(0)
        if auth_type == 2:
            conn.send('This page has been blocked for you!')
            exit(0)

        s.connect((webserver, port))
        s.sendall(request)

        if url in cache_time.keys():
            if if_modified_since == cache_modified_time[url]:
                print "Cache in USE"
                conn.send(cache[cache_key[url]])
            else:
                temps = ""
                while 1:
                    data = s.recv(buf_sz)
                    if (len(data) > 0):
                        conn.send(data)
                        temps += data
                    else:
                        break
                cache[cache_key[url]] = temps
                cache_time[url] = time.time()
                cache_modified_time[url] = if_modified_since
            exit(0)

        if url_count[url] >= 3:
            temps = ""
            if self.cache_cur < 3:
                while 1:
                    data = s.recv(buf_sz)
                    if (len(data) > 0):
                        conn.send(data)
                        temps += data
                    else:
                        break
                cache_key[url] = self.cache_cur
                cache[cache_key[url]] = temps
                cache_time[url] = time.time()
                cache_modified_time[url] = if_modified_since
                self.cache_cur += 1
            else:
                urls = ""
                url_ind = 3
                time_url = 1000000000000000000000000000
                for i in cache_time.keys():
                    if time_url > cache_time[i]:
                        time_url = cache_time[i]
                        url_ind = cache_key[i]
                        urls = i
                if urls != "":
                    del cache_key[urls]
                    del cache_time[urls]
                    del cache_modified_time[urls]
                    while 1:
                        data = s.recv(buf_sz)
                        if (len(data) > 0):
                            conn.send(data)
                            temps += data
                        else:
                            break
                    cache_key[url] = url_ind
                    cache[cache_key[url]] = temps
                    cache_time[url] = time.time()
                    cache_modified_time[url] = if_modified_since
        else:
            while 1:
                data = s.recv(buf_sz)
                if (len(data) > 0):
                    conn.send(data)
                else:
                    break


user_auths = []
admin_auths = []

f = open(AUTHENTICATION_FILE, 'r')
data = f.read()
data = data.splitlines()
for dat in data:
    user_auths.append(base64.b64encode(str(dat)))
f.close()

f = open(ADMINS_FILE, 'r')
data = f.read()
data = data.splitlines()
for dat in data:
    admin_auths.append(base64.b64encode(str(dat)))
f.close()

ser = Server()
ser.beg_thread()
