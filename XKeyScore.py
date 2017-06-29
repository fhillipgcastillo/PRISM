# XKeyScore
from scapy.all import sniff, Raw, IP, UDP
from shared import descriptBase64Content
import os

def filter_packat_by_string(pkt, string):
    if pkt.haslayer(Raw):
        raw_load = pkt.getlayer(Raw).field.get('load')
        if string in raw_load:
            print pkt.sprintf("""**QUERY FOUND:**\n
                From {IP: %IP.src% -> %IP.dst%\n}""")
            print raw_load

def searchString():
    string = raw_input("Word to search? ")
    for package in packagesData:
        filter_packat_by_string(package, string)

filesToRead = []
filesReaded = []
packagesData = []
dataset = "data\\"

def updateFilesToAnalize():
    global packagesData, filesToRead, filesReaded, dataset
    
    for root, dirs, files in os.walk(dataset):
        for file in files:
            if file not in filesReaded or filesToRead:
                if ".cap" in file or ".pcap" in file:
                    filesToRead.append(file)
def readPackages():
    global packagesData, filesToRead, filesReaded, dataset

    for file in filesToRead:
        pkgs = sniff(offline="%s%s"%(dataset, file))
        if len(packagesData) == 0:
            packagesData = pkgs
        else:
            packagesData += pkgs
        filesReaded.append(file)
        filesToRead.pop(filesToRead.index(file))

def analise():
    print "reading files..."
    updateFilesToAnalize()
    print "reading packages..."
    readPackages()


def showSumaries():
    global packagesData
    print len(packagesData)
    packagesData.nsummary()

def showRawData(begin=-1, ends=-1):
    global packagesData
    
    if ends < 0 and begin < 0: begin, ends = 0, len(packagesData)
    elif ends < begin: ends = begin

    for package in packagesData[begin:ends]:
        if package.haslayer(Raw):
            print "========%i========"%packagesData.index(package)
            print package.getlayer(Raw)
            print "=================="
    raw_input("press to continue... ")

def showRangeOfRawData():
    begin = raw_input("Which is the first package?/0 ") or 0
    ends = raw_input("Which is the last package? ") or 0
    showRawData(int(begin), int(ends))

def packet_callback(packet):
    # check to make sure it has a data payload
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
            print '[*] Server: %s' % packet[IP].dst
            print '[*] %s' %packet[TCP].payload

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)

def empty():
    pass

OPTIONS = [
    {
        'Label': 'Read & Analize dataset',
        'callback': analise
    },
    {
        'Label': 'Search for some string',
        'callback': searchString
    },
    {
        'Label': 'Show summary',
        'callback': showSumaries
    },
    {
        'Label': 'Summary from packageX to packageY',
        'callback': empty
    },
    {
        'Label': 'Show an specific package data',
        'callback': empty
    },
    {
        'Label': 'Show Raw Data',
        'callback': showRawData
    },
    {
        'Label': 'Show range of Raw packages',
        'callback': showRangeOfRawData
    },
    {
        'Label': 'Exit',
        'callback': exit
    },
]

def startOption(option):
    if int(option) >= len(OPTIONS ): return
    callback = OPTIONS[int(option)-1].get('callback')
    callback()
    manageOptions()

def manageOptions():
    options = """XKeyScore system\n
    Select an Option:\n"""
    for i in range(0, len(OPTIONS)):
        OPTION = OPTIONS[i]
        options += "%i) %s\n"%(i+1, OPTION.get('Label'))
    print options
    option = raw_input("Option: ")
    startOption(option)

def bootstrap():
    "analising files..."
    analise()
    manageOptions()



    