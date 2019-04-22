from scapy.all import sniff, Raw, IP, UDP, wrpcap, hexdump 
from shared import descriptBase64Content


def getSniffPackages(filter=False, count=10):
	try:
		pkts = sniff(filter=filter, count=count)
		return pkts
	except Exception as e:
		raise
	return []
packages = []

def monitorNetwork(filter=False, min_amount=10, DEBUG=False, save_pcks=False):
	_min=0
	_max = min_amount
	print "Starting to sniff every %i packages..."%min_amount
	global packages
	while True:
		pkts = getSniffPackages(filter, min_amount)
		# if save_pcks: wrpcap("data\\pkgs-%i-%i.cap"%(_min, _max), pkts)
		_min = _max
		_max += min_amount
		packages += pkts